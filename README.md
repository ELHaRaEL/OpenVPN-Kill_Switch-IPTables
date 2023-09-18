# OpenVPN-Kill_Switch-IPTables
Automatic kill switch using Iptables with OpenVPN

Full kill switch where when enabled only root can make any connection to VPN server only.

If the tunnel closes or crashes, only root can create the tunnel and connecting only to the IP and PORT needed to operate the tunnel.

# What does the script do?

It reads and displays all .ovpn files in our folder. We can choose one and after connection we can enable/disable the kill switch. Openvpn is working as daemon. When switching kill switch, iptables it flushes all rules, removes everything, then gives access to:
- Loopbacks and pings
- LAN communication
- Accepts tunnel exit/entry

If the kill switch is turned off, the settings can return to the backup or flush and open everything.

Before connection we can ping (10s) all vpns to measure average.
Ping terminals close after the task is completed and send information to the main window.

Killswitch can read domain adrress. (IP for iptable)

# What does the script need to work?

1. Add new system (-r) group:
```
groupadd -r vpnroute       
```
2. Add permission for the group so you don't have to enter the password every time.
Add in /etc/sudoers.d:
```
%vpnroute ALL=NOPASSWD: /usr/bin/killall openvpn
%vpnroute ALL=NOPASSWD: /usr/sbin/iptables
%vpnroute ALL=NOPASSWD: /usr/sbin/iptables-restore
%vpnroute ALL=NOPASSWD: /usr/sbin/iptables-save

USERNAME ALL=NOPASSWD: /usr/sbin/openvpn
```
3. Set in script path to folder with *.ovpn files and path to file with username and password. 
(--auth-user-pass)


# What the script uses to work?
```
openvpn 
iptables
killall
nslookup
curl
```
# iptables
    # Clear iptables
    sudo iptables --flush
    sudo iptables --delete-chain
    sudo iptables -t nat --flush
    sudo iptables -t nat --delete-chain
    # Drop everything
    sudo iptables -P INPUT DROP
    sudo iptables -P FORWARD DROP
    sudo iptables -P OUTPUT DROP
    # Forward - better watch iptables -S
    sudo iptables -A FORWARD
    # Allow Loopback and Ping
    sudo iptables -A INPUT -i lo -j ACCEPT
    sudo iptables -A OUTPUT -o lo -j ACCEPT
    # Allow to communicate within the LAN
    sudo iptables -A INPUT -s 192.168.1.0/24 -d 192.168.1.0/24 -i enp4s0 -j ACCEPT
    sudo iptables -A OUTPUT -s 192.168.1.0/24 -d 192.168.1.0/24 -o enp4s0 -j ACCEPT
    # Accept tunel out/in
    sudo iptables -A INPUT -i tun0 -j ACCEPT 
    sudo iptables -A OUTPUT -o tun0 -j ACCEPT 
    # Allow established sessions to receive traffic
    sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    # Allow vpn
    #sudo iptables -A OUTPUT -d x.x.x.x -p tcp --dport XX -m owner --uid-owner root -o $DEVICE -j ACCEPT


