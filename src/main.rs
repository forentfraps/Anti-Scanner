use pcap;
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use std::env;
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
                                    println!(
                                        "TCP Packet: {}:{} > {}:{}; Seq: {}, Ack: {}",
                                        ethernet_packet.get_source(),
                                        tcp_packet.get_source(),
                                        ethernet_packet.get_destination(),
                                        tcp_packet.get_destination(),
                                        tcp_packet.get_sequence(),
                                        tcp_packet.get_acknowledgement()
                                    );
                                }
                            }
                            IpNextHeaderProtocols::Udp => {
                                // Handle UDP packets
                                let udp_packet = UdpPacket::new(ethernet_packet.payload());
                                if let Some(udp_packet) = udp_packet {
                                    println!(
                                        "UDP Packet: {}:{} > {}:{}; Len: {}",
                                        ethernet_packet.get_source(),
                                        udp_packet.get_source(),
                                        ethernet_packet.get_destination(),
                                        udp_packet.get_destination(),
                                        udp_packet.get_length()
                                    );
                                }
                            }
                            _ => {
                                println!("protocol is {:?}", ipv4_packet.get_next_level_protocol());
                            }
                        }
                    }
                }
                _ => {
                    println!("ether type is {:?}", ethernet_packet.get_ethertype())
                }
            }
        }
    }
}
