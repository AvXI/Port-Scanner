# Port-Scanner
This code takes two arguments: --host which specifies the target IP address, and --ports which specifies the ports to scan (comma-separated). It uses the Scapy library to craft and send TCP SYN packets to each specified port, and then checks for SYN-ACK responses to determine whether the port is open or closed.
