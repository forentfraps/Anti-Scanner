use pnet::datalink::{self, Channel::Ethernet, NetworkInterface};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::{ethernet::EthernetPacket, Packet};
use std::env;

#[cfg(target_family = "unix")]
fn has_root_permissions() -> bool {
    nix::unistd::geteuid().is_root()
}

#[cfg(target_os = "windows")]
fn has_admin_permissions() -> bool {
    use std::ptr;
    use winapi::um::handleapi::INVALID_HANDLE_VALUE;
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
    let (_tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!(
            "An error occurred when creating the datalink channel: {}",
            e
        ),
    };

    loop {
        match rx.next() {
            Ok(raw_packet) => {
                let packet = EthernetPacket::new(raw_packet).unwrap();

                // This is where you would typically filter packets based on their type or perform
                // any specific action you need. Since we're making this a "catch-all", we'll
                // simply print out basic packet info.
                println!("Received a packet: {:?}", packet);
            }
            Err(e) => {
                eprintln!("An error occurred while reading: {}", e);
            }
        }
    }
}
