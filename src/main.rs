use pcap;
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use std::collections::{HashMap, HashSet};
use std::env;
use std::process::Command;

const ALLOWED_AMOUNT_OF_PORTS: usize = 25;

fn block_ip_win(ip: &str) {
    // Construct the netsh command to add a firewall rule
    let output = Command::new("netsh")
        .args(&[
            "advfirewall",
            "firewall",
            "add",
            "rule",
            "name=AntiScanner Blocked IP TCP", // Unique name for the rule
            &format!("remoteip={}", ip),       // The IP address to block
            "dir=in",                          // Direction: in = inbound, out = outbound
            "action=block",                    // Block the matching traffic
            "protocol=TCP", // Specify the protocol (optional, based on your needs)
            "enable=yes",   // Enable the rule
        ])
        .output()
        .expect("Failed to execute command");

    if output.status.success() {
        println!("IP {} successfully blocked TCP.", ip);
    } else {
        // Print the error output from the command for debugging
        eprintln!(
            "Error blocking IP {}: {}",
            ip,
            String::from_utf8_lossy(&output.stdout)
        );
    }
    let output = Command::new("netsh")
        .args(&[
            "advfirewall",
            "firewall",
            "add",
            "rule",
            "name=AntiScanner Blocked IP UDP", // Unique name for the rule
            &format!("remoteip={}", ip),       // The IP address to block
            "dir=in",                          // Direction: in = inbound, out = outbound
            "action=block",                    // Block the matching traffic
            "protocol=UDP", // Specify the protocol (optional, based on your needs)
            "enable=yes",   // Enable the rule
        ])
        .output()
        .expect("Failed to execute command");

    if output.status.success() {
        println!("IP {} successfully blocked UDP.", ip);
    } else {
        // Print the error output from the command for debugging
        eprintln!(
            "Error blocking IP {}: {}",
            ip,
            String::from_utf8_lossy(&output.stdout)
        );
    }
}
fn block_ip_unix(ip: &str) {
    let status = Command::new("sudo")
        .arg("iptables")
        .arg("-A")
        .arg("INPUT")
        .arg("-s")
        .arg(ip)
        .arg("-j")
        .arg("DROP")
        .status()
        .expect("Failed to execute iptables command");

    if status.success() {
        println!("Successfully blocked IP {}", ip);
    } else {
        eprintln!("Failed to block IP {}", ip);
    }
}
fn block_ip(ip: &str) {
    #[cfg(target_family = "unix")]
    {
        block_ip_unix(ip)
    }

    #[cfg(target_os = "windows")]
    {
        block_ip_win(ip)
    }

    #[cfg(not(any(target_family = "unix", target_os = "windows")))]
    {
        false // Or some default behavior for other platforms
    }
}

#[cfg(target_family = "unix")]
fn has_root_permissions() -> bool {
    nix::unistd::geteuid().is_root()
}

#[cfg(target_os = "windows")]
fn has_admin_permissions() -> bool {
    use std::ptr;

    use winapi::um::processthreadsapi::OpenProcessToken;
    use winapi::um::securitybaseapi;
    use winapi::um::winnt::{HANDLE, TOKEN_ELEVATION, TOKEN_QUERY};

    unsafe {
        let mut handle: HANDLE = ptr::null_mut();
        if OpenProcessToken(
            winapi::um::processthreadsapi::GetCurrentProcess(),
            TOKEN_QUERY,
            &mut handle,
        ) == 0
        {
            return false;
        }

        let mut elevation: TOKEN_ELEVATION = std::mem::zeroed();
        let mut size = std::mem::size_of::<TOKEN_ELEVATION>() as u32;
        let success = securitybaseapi::GetTokenInformation(
            handle,
            winapi::um::winnt::TokenElevation,
            &mut elevation as *mut _ as *mut _,
            size,
            &mut size,
        ) != 0;

        winapi::um::handleapi::CloseHandle(handle);

        success && elevation.TokenIsElevated != 0
    }
}
fn has_elevated_permissions() -> bool {
    #[cfg(target_family = "unix")]
    {
        has_root_permissions()
    }

    #[cfg(target_os = "windows")]
    {
        has_admin_permissions()
    }

    #[cfg(not(any(target_family = "unix", target_os = "windows")))]
    {
        false // Or some default behavior for other platforms
    }
}

fn catalog_packet(
    hm: &mut HashMap<String, HashSet<u16>>,
    hs: &mut HashSet<String>,
    ip: String,
    port: u16,
) {
    let mut ports_list = match hm.get_mut(&ip) {
        Some(vec) => vec,
        None => {
            hm.insert(ip.clone(), HashSet::new());
            hm.get_mut(&ip).unwrap()
        }
    };
    ports_list.insert(port);
    if ports_list.len() > ALLOWED_AMOUNT_OF_PORTS && !hs.contains(&ip) {
        block_ip(&(ip.to_string()));
        hs.insert(ip.clone());
    }
}

fn fail_start() -> ! {
    let interfaces = datalink::interfaces();
    println!("Please provide a valid interface index from this list:");

    // WIP
    // println!("[0] - All interfaces");
    for interface in interfaces.into_iter() {
        println!("[{:?}] -> {:?}", interface.index, interface);
    }
    std::process::exit(0);
}
fn main() {
    if !has_elevated_permissions() {
        println!("Restart with elevated permissions");
        std::process::exit(0);
    }
    let interface_name;
    match env::args().nth(1) {
        Some(iname) => {
            interface_name = iname;
        }
        None => fail_start(),
    }
    let interface_index = match interface_name.parse::<u32>() {
        Ok(number) => number,
        Err(_) => fail_start(),
    };
    let interface_names_match = |iface: &NetworkInterface| iface.index == interface_index;

    let interfaces = datalink::interfaces();
    // Find the network interface with the provided name
    let interface = match interfaces.into_iter().find(interface_names_match) {
        Some(_interface) => _interface,
        None => fail_start(),
    };

    // Create a new channel to capture packets
    let interface_name: &str = &(interface.name);
    let host_ip = interface.ips[0].ip();
    let mut cap = match pcap::Capture::from_device(interface_name)
        .unwrap()
        .promisc(true) // Set the capture mode to promiscuous
        .snaplen(5000) // Set the maximum bytes to capture per packet
        .open()
    {
        Ok(cap) => cap,
        Err(e) => {
            eprintln!("Error setting up the capture: {:?}", e);
            std::process::exit(0);
        }
    };
    let mut hs = HashSet::new();
    let mut hm = HashMap::new();
    while let Ok(packet) = cap.next() {
        // Parse the Ethernet frame from the captured packet data
        if let Some(ethernet_packet) = EthernetPacket::new(&packet.data) {
            match ethernet_packet.get_ethertype() {
                EtherTypes::Ipv4 => {
                    if let Some(ipv4_packet) = Ipv4Packet::new(ethernet_packet.payload()) {
                        // Check if the packet is TCP
                        match ipv4_packet.get_next_level_protocol() {
                            IpNextHeaderProtocols::Tcp => {
                                // Handle TCP packets
                                let tcp_packet = TcpPacket::new(ipv4_packet.payload());
                                if let Some(tcp_packet) = tcp_packet {
                                    // println!(
                                    //     "TCP Packet: From {} To {} {}:{} > {}:{}; Seq: {}, Ack: {}",
                                    //     ipv4_packet.get_source(),
                                    //     ipv4_packet.get_destination(),
                                    //     ethernet_packet.get_source(),
                                    //     tcp_packet.get_source(),
                                    //     ethernet_packet.get_destination(),
                                    //     tcp_packet.get_destination(),
                                    //     tcp_packet.get_sequence(),
                                    //     tcp_packet.get_acknowledgement()
                                    // );
                                    if ipv4_packet.get_destination() == host_ip {
                                        catalog_packet(
                                            &mut hm,
                                            &mut hs,
                                            ipv4_packet.get_source().to_string(),
                                            tcp_packet.get_source(),
                                        )
                                    }
                                }
                            }
                            IpNextHeaderProtocols::Udp => {
                                // Handle UDP packets
                                let udp_packet = UdpPacket::new(ethernet_packet.payload());
                                if let Some(udp_packet) = udp_packet {
                                    if ipv4_packet.get_destination() == host_ip {
                                        catalog_packet(
                                            &mut hm,
                                            &mut hs,
                                            ipv4_packet.get_source().to_string(),
                                            udp_packet.get_source(),
                                        );
                                    }
                                }
                            }
                            _ => {
                                //println!("protocol is {:?}", ipv4_packet.get_next_level_protocol());
                            }
                        }
                    }
                }
                _ => {
                    // println!("ether type is {:?}", ethernet_packet.get_ethertype())
                }
            }
        }
    }
}
