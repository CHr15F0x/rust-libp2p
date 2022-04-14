//! Boot node
//!
//! ```sh
//! cargo run --example chat-kad --features "tcp-tokio" -- -b
//! ```
//!
//! Other nodes
//!
//! ```sh
//! cargo run --example chat-kad --features "tcp-tokio"
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

    let boot_secret = identity::ed25519::SecretKey::from_bytes([
        186, 94, 235, 142, 154, 80, 34, 64, 1, 217, 93, 119, 94, 209, 51, 226, 225, 191, 141, 5,
        251, 255, 214, 189, 103, 90, 198, 205, 175, 238, 170, 216,
    ])
    .unwrap();
    let boot_key = identity::Keypair::Ed25519(identity::ed25519::Keypair::from(boot_secret));

    let (my_key, boot_peer_id) = match std::env::args().nth(1) {
        // I am the boot node
        Some(arg) => {
            assert_eq!(arg, "-b", "Use -b to run a boot node!");
            (boot_key, None)
        }
        // I am a normal node
        None => (
            identity::Keypair::generate_ed25519(),
            Some(PeerId::from(boot_key.public())),
        ),
    };

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
        // We don't want to be re-adding those nodes that have already been added
        // as the Identify events will show up regularly
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
                        info!("KademliaEvent::{event:#?}");
                    } else {
                        trace!("KademliaEvent::{event:#?}");
                    }
                }
                other_kad_event => {
                    trace!("KademliaEvent::{other_kad_event:?}");
                }
            }
        }
    }

    impl NetworkBehaviourEventProcess<IdentifyEvent> for MyBehaviour {
        fn inject_event(&mut self, event: IdentifyEvent) {
            // When looking for closest peers to a key in return we only get peer IDs but no
            // listening addresses of those peers.
            // This is to know what the listening addresses of other nodes are.
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
                trace!("IdentifyEvent::{event:#?}");
            }
        }
    }

    #[allow(non_snake_case)]
    let ONE_MINUTE = Duration::from_secs(60);
    #[allow(non_snake_case)]
    let FOREVER: Option<Duration> = None;

    const PROTOCOL: &[u8; 21] = b"/chris_chat/kad/1.0.0";

    // Create a Swarm to manage peers and events.
    let mut swarm = {
        let mut cfg = KademliaConfig::default();
        cfg.set_query_timeout(ONE_MINUTE)
            .set_provider_publication_interval(Some(ONE_MINUTE))
            .set_provider_record_ttl(FOREVER)
            .set_publication_interval(Some(ONE_MINUTE))
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
    } else {
        // Listen on all interfaces and a chosen port if we're the boot node
        swarm.listen_on("/ip4/0.0.0.0/tcp/55555".parse()?)?;
    }

    // Do some logging regularly
    let mut dump_interval = tokio::time::interval(Duration::from_secs(20));

    // Look for peers closest to some random key to see if it helps add more peers to the DHT
    let mut closest_discovery_interval = tokio::time::interval(Duration::from_secs(60));

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
                            .map(|entry| (entry.node.key.preimage().clone(), entry.node.value.clone(), entry.status))
                            .collect::<Vec<_>>())
                        .collect::<Vec<Vec<_>>>()
                );
            }
            _ = closest_discovery_interval.tick() => {
                if !swarm.behaviour_mut().i_am_boot {
                    let rnd_key: PeerId = identity::Keypair::generate_ed25519().public().into();
                    info!("Get closest peers to rnd key: {:?}",
                        swarm.behaviour_mut().kad.get_closest_peers(rnd_key));
                }
            }
        }
    }
}
