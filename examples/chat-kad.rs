//! Boot node
//!
//! ```sh
//! cargo run --example chat-kad --features "tcp-tokio"
//! ```
//!
//! Other nodes
//!
//! ```sh
//! cargo run --example chat-kad --features "tcp-tokio" -- PeerId_of_Boot_Node
//! ```

use futures::StreamExt;
use libp2p::{
    core::{muxing, transport, upgrade},
    identify::{Identify, IdentifyConfig, IdentifyEvent},
    identity,
    kad::{record::store::MemoryStore, Kademlia, KademliaConfig, KademliaEvent, QueryResult},
    mplex,
    noise,
    swarm::{NetworkBehaviourEventProcess, SwarmBuilder, SwarmEvent},
    // Requires `tcp-tokio` feature.
    tcp::TokioTcpConfig,
    websocket,
    yamux,
    Multiaddr,
    NetworkBehaviour,
    PeerId,
    Transport,
};
use log::{debug, info, trace};
use std::{borrow::Cow, collections::HashSet, error::Error, str::FromStr, time::Duration};
use tokio::io::{self, AsyncBufReadExt};

pub async fn tokio_development_transport(
    keypair: identity::Keypair,
) -> std::io::Result<transport::Boxed<(PeerId, muxing::StreamMuxerBox)>> {
    let transport = {
        let tcp = TokioTcpConfig::new().nodelay(true);
        let ws_tcp = websocket::WsConfig::new(tcp.clone());
        tcp.or_transport(ws_tcp)
    };

    let noise_keys = noise::Keypair::<noise::X25519Spec>::new()
        .into_authentic(&keypair)
        .expect("Signing libp2p-noise static DH keypair failed.");

    Ok(transport
        .upgrade(upgrade::Version::V1)
        .authenticate(noise::NoiseConfig::xx(noise_keys).into_authenticated())
        .multiplex(upgrade::SelectUpgrade::new(
            yamux::YamuxConfig::default(),
            mplex::MplexConfig::default(),
        ))
        .timeout(std::time::Duration::from_secs(20))
        .boxed())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "chat_kad=info");
    }

    env_logger::builder().format_timestamp(None).init();

    let boot_peer_id = std::env::args()
        .nth(1)
        .map(|x| PeerId::from_str(&x).expect("A valid PeerId"));

    // Create a random key for ourselves.
    let my_key = identity::Keypair::generate_ed25519();
    let my_key_public = my_key.public();
    let my_peer_id = PeerId::from(my_key_public.clone());
    info!("My peer id: {my_peer_id:?}");

    if boot_peer_id.is_some() {
        info!("Boot peer id {boot_peer_id:?}");
    } else {
        info!("I am the boot node!");
    }

    let transport = tokio_development_transport(my_key).await?;

    #[derive(NetworkBehaviour)]
    #[behaviour(event_process = true)]
    struct MyBehaviour {
        kad: Kademlia<MemoryStore>,
        identify: Identify,
        // Helps us distinguish if this is a boot node or not
        #[behaviour(ignore)]
        i_am_boot: bool,
        // We don't want to be re-adding those nodes that have already been added by the boot node
        // as the Identify events will show up regularly
        // This is only used by the boot node
        #[behaviour(ignore)]
        identify_cache: HashSet<PeerId>,
    }

    impl NetworkBehaviourEventProcess<KademliaEvent> for MyBehaviour {
        fn inject_event(&mut self, event: KademliaEvent) {
            match event {
                KademliaEvent::OutboundQueryCompleted {
                    result: QueryResult::Bootstrap(result),
                    ..
                } => match result {
                    Ok(r) => {
                        debug!("{r:#?}");
                        if r.num_remaining == 0 {
                            info!("Bootstrap completed!");
                        }
                    }
                    Err(e) => info!("{e:#?}"),
                },
                KademliaEvent::RoutingUpdated {
                    is_new_peer,
                    peer: _,
                    old_peer: _,
                    ..
                } => {
                    if is_new_peer {
                        // I wanna see only the new peers added to the DHT
                        info!("{event:#?}");
                    } else {
                        trace!("{event:#?}");
                    }
                }
                other_kad_event => {
                    trace!("{other_kad_event:?}");
                }
            }
        }
    }

    impl NetworkBehaviourEventProcess<IdentifyEvent> for MyBehaviour {
        fn inject_event(&mut self, event: IdentifyEvent) {
            if self.i_am_boot {
                // This is only required for the boot node.
                // I still don't understand exactly if this is normal but apparently
                // when the boot node is added manually by other nodes it means that
                // the boot node will not know what the listening addresses of those other nodes are.
                // We are fixing it with the Identity protocol.
                //
                // Based on this discussion:
                // https://github.com/libp2p/rust-libp2p/discussions/2447#discussioncomment-2053119
                // Linked src by mxinden
                // https://github.com/mxinden/rust-libp2p-server/blob/35aad8be33962d565ac8fe1cf63679418a1b1189/src/main.rs#L129-L156
                //
                // `identify_cache` is here to avoid reloggin and readding as this example is for some limited tests only
                // and I don't anticipate a listening address change honestly
                if let IdentifyEvent::Received { peer_id, info } = event {
                    if !self.identify_cache.contains(&peer_id)
                        && info.protocols.iter().any(|p| p.as_bytes() == PROTOCOL)
                    {
                        info!(
                            "IdentifyEvent::Received, add addresses of {peer_id:?} {:#?}",
                            info.listen_addrs
                        );

                        for addr in info.listen_addrs {
                            self.kad.add_address(&peer_id, addr);
                        }

                        // Don't add nor log again
                        self.identify_cache.insert(peer_id);
                    }
                } else {
                    trace!("{event:#?}");
                }
            }
        }
    }

    #[allow(non_snake_case)]
    let ONE_MINUTE = Duration::from_secs(60);
    #[allow(non_snake_case)]
    let TEN_MINUTES = Duration::from_secs(600);
    #[allow(non_snake_case)]
    let FOREVER: Option<Duration> = None;

    const PROTOCOL: &[u8; 21] = b"/chris_chat/kad/1.0.0";

    // Create a Swarm to manage peers and events.
    let mut swarm = {
        let mut cfg = KademliaConfig::default();
        cfg.set_query_timeout(ONE_MINUTE)
            .set_provider_publication_interval(Some(ONE_MINUTE))
            .set_provider_record_ttl(FOREVER)
            .set_publication_interval(Some(TEN_MINUTES))
            .set_record_ttl(FOREVER)
            .set_replication_interval(Some(ONE_MINUTE))
            .set_protocol_name(Cow::from(&PROTOCOL[..]));
        let store = MemoryStore::new(my_peer_id);
        let mut kad = Kademlia::with_config(my_peer_id, store, cfg);

        if let Some(some_boot_peer_id) = boot_peer_id {
            // Add the bootnode to the local routing table.
            // We assume that the boot node is ran on the very same host and that the port is known.
            kad.add_address(
                &some_boot_peer_id,
                Multiaddr::from_str("/ip4/127.0.0.1/tcp/55555").unwrap(),
            );
        }

        let behaviour = MyBehaviour {
            kad,
            // To fix UnroutablePeer errors in the boot node where we dunno what the listening adress of a peer is
            identify: Identify::new(IdentifyConfig::new(
                "/chris_chat/identify/1.0.0".to_string(),
                my_key_public,
            )),
            i_am_boot: boot_peer_id.is_none(),
            identify_cache: HashSet::new(),
        };

        SwarmBuilder::new(transport, behaviour, my_peer_id)
            // We want the connection background tasks to be spawned onto the tokio runtime.
            .executor(Box::new(|fut| {
                tokio::spawn(fut);
            }))
            .build()
    };

    // Read full lines from stdin
    let mut stdin = io::BufReader::new(io::stdin()).lines();

    if boot_peer_id.is_some() {
        // Listen on all interfaces and whatever port the OS assigns
        swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;
        // Start the bootstrap process
        info!(
            "Start bootstrap: {:?}",
            swarm.behaviour_mut().kad.bootstrap()
        );
    } else {
        // Listen on all interfaces and a chosen port if we're the boot node
        swarm.listen_on("/ip4/0.0.0.0/tcp/55555".parse()?)?;
    }

    // Do some logging regularly
    let mut dump_interval = tokio::time::interval(Duration::from_secs(20));

    // Log the protocol name
    info!(
        "Kad protocol name: {}",
        std::str::from_utf8(swarm.behaviour_mut().kad.protocol_name()).unwrap()
    );

    // Kick it off
    loop {
        tokio::select! {
            line = stdin.next_line() => {
                let _line = line?.expect("stdin closed");
            }
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        info!("Listening on {address:?}");
                    }
                    swarm_event => {
                        trace!("{swarm_event:#?}");
                    }
                }
            }
            _ = dump_interval.tick() => {
                // trace!("{:#?}", swarm.network_info());
                info!(
                    "Peers conn.: {} kad.: {}",
                    swarm.connected_peers().count(),
                    swarm
                        .behaviour_mut()
                        .kad
                        .kbuckets()
                        .map(|kbucket| kbucket.num_entries())
                        .reduce(|acc, item| acc + item)
                        .unwrap_or_default()
                );
                // Show currently connected peers
                trace!("Peers conn.: {:#?}", swarm.connected_peers().collect::<Vec<_>>());
                // Show peers in the buckets
                debug!(
                    "Peers kad.: {:#?}",
                    swarm
                        .behaviour_mut()
                        .kad
                        .kbuckets()
                        .map(|kbucket| kbucket
                            .iter()
                            .map(|entry| entry.node.key.preimage().clone())
                            .collect::<Vec<_>>())
                        .collect::<Vec<Vec<_>>>()
                );
            }
        }
    }
}
