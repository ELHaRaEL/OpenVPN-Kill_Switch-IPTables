#!/bin/bash
######################################



######################################
### MODIFY
###################
DEVICE=enp4s0
TUN=tun0
VPNGROUP=vpnroute
###################

VPNFOLDER="$(pwd)/VPN"
#folder with .ovpn files

PASSWORDFILE="$(pwd)/auth-user-pass"
#file with username & password like:
#username
#password

ping_time=10
ping_delay=0.5

###################
### END MODIFY
######################################



######################################
startip="Without checking on start"
Kill_Switch=false
declare -a IPSandPORTS=()  # for kill switch
declare -a IPs=()  # for pings
declare -a FilesNames=()  # .ovpn
declare -a FilesNamesToSelect=()   # .ovpn
declare -a CountSuccesPing=()

function Ping_All_VPNs
{
results=()
animation="-\|/"
animation2="...."
animation3="    "
echo -e "\n"

    for (( i=0; i<=${#IPs[@]}; i++ ))
        do
        gnome-terminal --geometry=1x1+1+1 --hide-menubar -- sh -c "ping -w $ping_time -i $ping_delay ${IPs[i]} | grep -oP '(?<=time=)[0-9.]+' | awk '{ sum += \$1; n++ } END { if (n >= 0) printf \"\n%-3d     %-16s %6.2f ms    ${FilesNames[i]} \", $((i+1)), \"${IPs[i]}\", sum / n }' | tee $(tty) | { read -r result; printf -v \"results[$i]\" '%s' \"\$result\"; } "  & 
        done
    wait
    Time=0
    while [ "$Time" -lt "$((ping_time-2))" ]
        do
          for i in $(seq 0 3)
             do
                echo -ne "\rPlease wait${animation2:0:$((i+1))}${animation3:0:$((4-i))}  pinging${animation2:0:$((i+1))}${animation3:0:$((4-i))}      ${animation:$i:1}    $((ping_time-1-Time))s   ${animation:$i:1}   ${animation2:0:$((i+1))}${animation3:0:$((4-i))}  "
                sleep 1
                ((Time++))
            done
        done
    echo -e "\n\n\nNo.      IP               Average     Filename"
    wait
    sleep 5
    echo -e "\n\n${CountSuccesPing}/${#IPs[@]}  servers have been pinged"
}

function Read_IPs_From_ovpn_Files {
    IPs=()
    FilesNames=()
    CountSuccesPing=0

    for file in $VPNFOLDER/*.ovpn; do
        for server in $(grep -oP '(?<=remote\s)[^[:space:]]+' "$file" | sort -u); do
            if [[ ! " ${IPs[@]} " =~ " ${server} " ]]; then
                if [[ $server =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                    IPs+=("$server")
                    FilesNames+=("$(basename "$file")")    
                    ((CountSuccesPing++))
                else
                    ip=$(nslookup "$server" | awk '/^Address: / { print $2 }')
                    if [[ -n $ipDataIp ]]; then
                        IPs+=("$ipDataIp")
                        ((CountSuccesPing++))
                        FilesNames+=("$(basename "$file")")
                    else
                        IPs+=("$server")
                        FilesNames+=("$(basename "$file")")       
                    fi
                fi
            fi
        done
    done
}


function Read_ovpn_Files
{
    FilesNamesToSelect=()
    while read filename
    do
        FilesNamesToSelect+=($filename)
    done < <(ls -A1 $VPNFOLDER/*.ovpn | sed -e 's/.*\///g') 
}


function Select_VPN 
{
animation="-\|/-"
animation5="54321"
PS3="Enter a number: "
select ovpn in ${FilesNamesToSelect[*]}
    do
        if [[ "$REPLY" =~ ^[0-9]+$ ]]; then
        if [ $REPLY -le ${#FilesNamesToSelect[*]} ]; then
            clear
            sudo openvpn --config "$VPNFOLDER/$ovpn" --daemon --auth-user-pass "$PASSWORDFILE"
            echo -e "Choosed: $ovpn\n"
              for i in $(seq 0 4)
                 do
                    echo -ne "\r   ${animation:$i:1}   Waiting ${animation5:$i:1}s to check your actually IP   ${animation:$i:1}"
                    sleep 1
                done
            clear
            Check_Actualy_IP
            return
        fi
        fi
        case $REPLY in
            p|P|ping)  Read_IPs_From_ovpn_Files; Ping_All_VPNs ;;
        esac
    done
}


function Show_Intro
{
    echo "//////////       OpenVPN - Choose Virtual Private Network       \\\\\\\\\\\\\\\\\\\\"
    echo -e "\nYour IP at start:     $startip"; 
    echo -e "\np)   P|ping|Ping)     Ping all vpns (10s)\n\n"; 
}

function Save_Backup
{
    if [ -e iptables.conf ]; then
      read -p "The iptables.conf file already exists. Do you want to overwrite it? [Y/N]" answer
      if [[ $answer =~ [Yy] ]]; then
        sudo -g $VPNGROUP sudo iptables-save > iptables.conf
        echo -e "\n$(sudo -g $VPNGROUP sudo iptables-save)\n" >> iptables-backup.conf
        echo -e "The iptables.conf file has been overwritten.\nAll backups with timestamp are in iptables-backup.conf"
      else
        echo "The iptables.conf file was not overwritten."
      fi
    else
      sudo -g $VPNGROUP sudo iptables-save > iptables.conf
      echo -e "\n$(sudo -g $VPNGROUP sudo iptables-save)\n" >> iptables-backup.conf
      echo -e "The iptables.conf file has been saved.\nAll backups with timestamp are in iptables-backup.conf"
    fi
}

function Flush_IPTables
{
    sudo -g $VPNGROUP sudo iptables --flush
    sudo -g $VPNGROUP sudo iptables --delete-chain
    sudo -g $VPNGROUP sudo iptables -t nat --flush
    sudo -g $VPNGROUP sudo iptables -t nat --delete-chain
    sudo -g $VPNGROUP sudo iptables -P INPUT ACCEPT
    sudo -g $VPNGROUP sudo iptables -P FORWARD ACCEPT
    sudo -g $VPNGROUP sudo iptables -P OUTPUT ACCEPT
    Kill_Switch=false
}

function Read_IPandPORTS_from_ovpn_file 
{
  IPSandPORTS=()
  while read -r line; do
    if [[ "$line" == "remote "* ]]; then
        domain=$(echo "$line" | awk '{ print $2 }')
        port=$(echo "$line" | awk '{ print $3 }')
             if [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                    IPSandPORTS+=("$domain $port")
             else
                   ip=$(nslookup "$domain" | awk '/^Address: / { print $2 }')
                   if [[ -n $ipDataIp ]]; then
                       IPSandPORTS+=("$domain $port")
                   fi
             fi
    fi
  done < "$VPNFOLDER/$ovpn"
}

function Block_All_Traffic
{
    clear
    sudo -g $VPNGROUP sudo iptables --flush
    sudo -g $VPNGROUP sudo iptables --delete-chain
    sudo -g $VPNGROUP sudo iptables -t nat --flush
    sudo -g $VPNGROUP sudo iptables -t nat --delete-chain
    sudo -g $VPNGROUP sudo iptables -P INPUT DROP
    sudo -g $VPNGROUP sudo iptables -P FORWARD DROP
    sudo -g $VPNGROUP sudo iptables -P OUTPUT DROP
    sudo -g $VPNGROUP sudo iptables -S
    echo -e "\nAll traffic blocked\n"
}

function Check_Actualy_IP
{
    echo -e "Trying to check IP - ipinfo.io/ip ... timeout 10s"
    ipData=$(sg vpnroute -c 'curl --fail --silent --show-error --max-time 10 ipinfo.io') > /dev/null    
    ipDataIp=$(echo "$ipData" | grep '"ip"' | sed -n 's/[^"]*"[^"]*"[^"]*"\([^"]*\)".*/\1/p')
    ipDataHostname=$(echo "$ipData" | grep '"hostname"' | sed -n 's/[^"]*"[^"]*"[^"]*"\([^"]*\)".*/\1/p' ) 
    ipDataCity=$(echo "$ipData" | grep '"city"' | sed -n 's/[^"]*"[^"]*"[^"]*"\([^"]*\)".*/\1/p' )
    ipDataRegion=$(echo "$ipData" | grep '"region"' | sed -n 's/[^"]*"[^"]*"[^"]*"\([^"]*\)".*/\1/p' )
    ipDataCountry=$(echo "$ipData" | grep '"country"' | sed -n 's/[^"]*"[^"]*"[^"]*"\([^"]*\)".*/\1/p' )
    ipDataLocalization=$(echo "$ipData" | grep '"loc"' | sed -n 's/[^"]*"[^"]*"[^"]*"\([^"]*\)".*/\1/p' )
    ipDataOrganization=$(echo "$ipData" | grep '"org"' | sed -n 's/[^"]*"[^"]*"[^"]*"\([^"]*\)".*/\1/p' )
    ipDataTimezone=$(echo "$ipData" | grep '"timezone"' | sed -n 's/[^"]*"[^"]*"[^"]*"\([^"]*\)".*/\1/p' )
    clear
    echo -e "Configuration .ovpn file: $ovpn\n\nYour IP at start: $startip\nActually IP:      $ipDataIp\n"
    echo -e "Hostname:         $ipDataHostname"
    echo -e "Organization:     $ipDataOrganization"
    echo -e "Localization:     $ipDataCountry -- $ipDataRegion -- $ipDataCity -- [$ipDataLocalization]"
    echo -e "Timezone:         $ipDataTimezone"
}

function Check_Start_IP
{
    echo -e "Trying to check IP - ipinfo.io/ip ... timeout 10s"
    startip=$(curl --fail --silent --show-error --max-time 10 ipinfo.io/ip) > /dev/null 
    clear
}
function Kill_Switch
{
    Read_IPandPORTS_from_ovpn_file
    # Clear iptables
    sudo -g $VPNGROUP sudo iptables --flush
    sudo -g $VPNGROUP sudo iptables --delete-chain
    sudo -g $VPNGROUP sudo iptables -t nat --flush
    sudo -g $VPNGROUP sudo iptables -t nat --delete-chain

    # Allow vpn
    for index in "${IPSandPORTS[@]}"
        do
            sudo -g $VPNGROUP sudo iptables -A OUTPUT -d "${index% *}" -p tcp --dport "${index#* }" -m owner --uid-owner root -o $DEVICE -j ACCEPT
        done

    # Allow established sessions to receive traffic
    sudo -g $VPNGROUP sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    # Forward - better watch iptables -S
    sudo -g $VPNGROUP sudo iptables -A FORWARD
    # Allow Loopback and Ping
    sudo -g $VPNGROUP sudo iptables -A INPUT -i lo -j ACCEPT
    sudo -g $VPNGROUP sudo iptables -A OUTPUT -o lo -j ACCEPT
    # Allow to communicate within the LAN
    sudo -g $VPNGROUP sudo iptables -A INPUT -s 192.168.1.0/24 -d 192.168.1.0/24 -i $DEVICE -j ACCEPT
    sudo -g $VPNGROUP sudo iptables -A OUTPUT -s 192.168.1.0/24 -d 192.168.1.0/24 -o $DEVICE -j ACCEPT
    # Accept tunel out/in
    sudo -g $VPNGROUP sudo iptables -A INPUT -i $TUN -j ACCEPT 
    sudo -g $VPNGROUP sudo iptables -A OUTPUT -o $TUN -j ACCEPT 
  
    # Drop everything
    sudo -g $VPNGROUP sudo iptables -P INPUT DROP
    sudo -g $VPNGROUP sudo iptables -P FORWARD DROP
    sudo -g $VPNGROUP sudo iptables -P OUTPUT DROP
    Kill_Switch=true
}



#////////////////////////////////////
processid=$(pgrep openvpn);
    if [ -n "$processid" ]; then
        echo "OpenVPN process detected:"| pgrep openvpn
        echo "Kill all OpenVPN process?"
        echo "[y/n]"
        read ans
            case $ans in
                Y|y|yes|1 )  echo "Yes"; sudo -g $VPNGROUP sudo killall openvpn ;;
                N|n|no|2  )  echo "No";;
                *         )  echo "Default - killall openvpn process"; sudo -g $VPNGROUP sudo killall openvpn ; exit ;;
            esac
        sleep 2
        clear
    fi
echo "Check IP   Reset iptables & check IP          sudo iptables -S"
echo -e "C-heck     R-eset                                  I-ptables\n"
echo "B-lock all traffic                                 S-ave backup iptables"
echo "                                                   L-oad last backup iptables"
read ans
    case $ans in
        B|b )  Block_All_Traffic ;;
        C|c )  clear ; Check_Start_IP ;;
        I|i )  clear ; sudo -g $VPNGROUP sudo iptables -S ; echo -e "\n\n" ;;
        R|r )  clear ; Flush_IPTables ; sudo -g $VPNGROUP sudo iptables -S ; Check_Start_IP ;;
        S|s )  clear ; Save_Backup ;;
        L|l )  clear ; sudo -g $VPNGROUP sudo iptables-restore < iptables.conf ;   echo -e "The iptables.conf file has been restored.";;
         *  )  clear ;;
    esac

Read_ovpn_Files
Show_Intro
Select_VPN

while true; do
    echo -e "\n                                           Kill_Switch:  "$Kill_Switch
    echo "What's next?"
    echo "1) Check IP (curl ipinfo.io)"
    echo "2) Check is openvpn working"
    echo -e "3) sudo -g $VPNGROUP sudo killall openvpn  &  go to menu"

    echo "5) Block all traffic & sudo -g $VPNGROUP sudo iptables -S"
    echo "6) Set Kill_Switch & sudo -g $VPNGROUP sudo iptables -S"
    echo "7) Flush iptables ipv4"   
    echo "8) sudo -g $VPNGROUP sudo iptables -S"
    echo "9) ping -c 5 1.1.1.1"
    echo "21) Save iptable backup"
    echo "22) Restore iptable backup"
    echo "Q) Quit"
    echo -n $PS3
    read anwser
    case "${anwser^^}" in
        "1") clear ; Check_Actualy_IP ;;
        "2") clear ; echo "Process ID:"; pgrep openvpn  ;;
        "3") sudo -g $VPNGROUP sudo killall openvpn ; clear ; Show_Intro ; Select_VPN ;;
        "5") Block_All_Traffic ;;
        "6") Kill_Switch ; sudo -g $VPNGROUP sudo iptables -S ;;       
        "7") Flush_IPTables ; sudo -g $VPNGROUP sudo iptables -S ;;
        "8") sudo -g $VPNGROUP sudo iptables -S;;
        "9") ping -c 5 1.1.1.1 | ts ;;
        "21") Save_Backup ;;
        "22") sudo -g $VPNGROUP sudo iptables-restore < iptables.conf ; echo -e "The iptables.conf file has been restored.";;
        "Q") break ;;
        *) echo "You must choose!" ;;
    esac
done
