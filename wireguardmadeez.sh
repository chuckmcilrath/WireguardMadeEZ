#!/bin/bash

########################################################################################################################################################################################
#                                                                                                                                                                                      #
# wget -O wireguardmadeez.sh https://raw.githubusercontent.com/chuckmcilrath/WireguardMadeEZ/refs/heads/main/wireguardmadeez.sh && chmod +x wireguardmadeez.sh && ./wireguardmadeez.sh #
#                                                                                                                                                                                      #
########################################################################################################################################################################################

####################
# GLOBAL VARIABLES #
####################

resolved_path=/etc/systemd/resolved.conf
net_interf=/etc/network/interfaces
interf=$(grep '^\s*iface\s\+\w\+\s\+inet\s\+static' /etc/network/interfaces | awk '{print $2}')

####################
# GLOBAL FUNCTIONS #
####################

# Check for root permissions.
check_root() {
	if [[ $EUID -ne 0 ]]; then
		echo "This script must be run as root. Please use sudo or log in as root." >&2
		exit 1
	fi
}

run_apt_update() {
	export DEBIAN_FRONTEND=noninteractive
 	apt update &> /dev/null
  	echo "Apt update has been completed."
}

# Check to see if an app is installed.
check_install() {
	local install_name="$1"

	echo "looking for $install_name..."
	if ! dpkg -l | awk '{print $2}' | grep -xq "$install_name"; then
		echo "Installing $install_name..."
		apt install $install_name -y &> /dev/null
		if dpkg -l | awk '{print $2}' | grep -xq "$install_name"; then
			echo "$install_name has been successfully installed."
		else
			echo "Installation failed. Please clear the error and try again."
		exit 1
		fi
	else
		echo "$install_name is already installed. Continuing..."
	fi
}

# Check if user entered IP is valid
is_valid_ip() {
	local ip=$1
	local IFS='.'
	local -a octets=($ip)

	[[ "${octets[0]}" -eq 127 ]] && return 1
	[[ ${#octets[@]} -ne 4 ]] && return 1

	# Check each octet is between 0 and 255
	for octet in "${octets[@]}"; do
		[[ ! "$octet" =~ ^[0-9]+$ ]] && return 1
		((octet < 0 || octet > 255)) && return 1
	done

return 0
}

# Check the user's CIDR input to make sure it's within 0-32
cidr_check() {
	local cidr=$1

	[[ $cidr =~ ^[0-9]+$ ]] || return 1
	((cidr >= 0 && cidr <= 32))
}

# Check user input is 256-bit key for Wireguard configuration file.
key_check() {
	local key="$1"

	[[ "$key" =~ ^[A-Za-z0-9+/]{43}=$ ]] && return 0
	return 1
}

# Check user input is 
port_num_check() {
	local num="$1"

	[[ ! $num =~ ^[1-9][0-9]*$ ]] && return 1
	(( num < 1 || num > 65535 )) && return 1

	return 0
}

# User input for config name
config_file_creation() {
	echo -e "/nName your Wireguard Port. This will be used for the config file name."
 	echo "EXAMPLE: server, wg0, wg1, wg2, etc."
  	read -p ": " wg_port_name
   	touch /etc/wireguard/"$wg_port_name".conf
	config_path="/etc/wireguard/${wg_port_name}.conf"
}

# Checks to see if the config file is already there, if it is, it will break.
config_file_check() {
	if ls /etc/wireguard/*.conf >/dev/null 2>&1; then
		echo " ***WARNING*** Wireguard config found, please run the cleanup option if you need to reinstall."
		return 1
	fi
}

# print the public key for the user to use in clients.
print_public_key() {
	echo -e "\nPrinting the Public key\n\n$public_key\n\n"
	echo "Please copy this key to use for setting up the client"
}
##################
# MENU FUNCTIONS #
##################

# Main menu of the wireguard script.
main_menu() {
	echo
	cat << EOF
              ###################
              #### MAIN MENU ####
              ###################

Choose the install type:

1. (OPTIONAL) Set Static IP
2. Wireguard Server Install and Setup
3. Wireguard Server Peer Config
4. Client Peer Install and Setup
5. Client Peer Config
6. Troubleshooting and help
7. Delete and cleanup

Type "exit" to exit the script.
EOF

read -p ": " install_type
}

# Checked the network config for DHCP. Changes to static if it is.
main_1_DHCP_check() {
	echo "Setting up network config file for static deployment"
	if grep -q dhcp $net_interf; then
		sed -i 's/dhcp/static/' $net_interf \
		&& echo -e "        address\n        gateway" >> $net_interf
	fi
}

# Edits the IP (Only the IP)
main_1_static_ip_edit() {
	echo -e "\n***WARNING***\nOnce you change the IP, you WILL be disconnected.\nYou will need to re-connect using the correct IP.\n"
	while true; do
		read -p $'Input the static IP you would like the Wireguard Server to use. (e.g. 192.168.1.2)\n: ' static_ip
		if is_valid_ip "$static_ip"; then
			while true; do
				echo "Are you sure you want to use $static_ip? (y/n)"
				read -p ": " static_confirm
				if [[ $static_confirm == y ]]; then
					if grep -q address $net_interf; then
						sed -i "/address/c\        address "$static_ip" " $net_interf \
						&& echo "Address has been changed."
						break 2
					else
						echo -e "Failed to change address. Please make sure dhcp is on the correct line.\nExiting Script."
						exit 1
					fi
				elif [[ $static_confirm == n ]]; then
					echo "Please try again."
					break
				else
					echo "not a valid answer. Please use \"y\" or \"n\"."
				fi
			done
		else
			echo "not a valid IP. Please enter a valid IP."
		fi
	done
}

# Adds the CIDR notation to the end of the user inputed static IP.
main_1_cidr_edit() {
while true; do
	read -p $'Enter the subnet in CIDR notation. (e.g. 24)\n: ' cidr_input
	if cidr_check "$cidr_input"; then
		while true; do
			echo "Are you sure you want to use $cidr_input? (y/n)"
			read -p ": " cidr_confirm
			if [[ $cidr_confirm == y ]]; then
				if grep -q "$static_ip" $net_interf; then
					sed -i "/"$static_ip"/c\        address "$static_ip"\/"$cidr_input" " $net_interf \
					&& echo "Subnet has been added."
					break 2
				else
					echo -e "Failed to change subnet. Please make sure dhcp is on the correct line.\nExiting Script."
					exit 1
				fi
			elif [[ $cidr_confirm == n ]]; then
				echo "Please try again."
			else
				echo "not a valid answer. Please use \"y\" or \"n\"."
			fi
		done
	else
		echo "Not a valid input. Please choose a number 0-32."
	fi
done
}

# Edits the gateway for static IP
main_1_gateway_edit() {
	while true; do
		read -p $'Input the gateway\n: ' static_gw
		if is_valid_ip "$static_gw"; then
			while true; do
				echo "Are you sure you want to use $static_gw? (y/n)"
				read -p ": " static_gw_confirm
				if [[ $static_gw_confirm = y ]]; then
					if grep -q address $net_interf; then
						sed -i "/gateway/c\        gateway "$static_gw" " $net_interf \
						&& echo "Gateway has been changed."
						break 2
					else
						echo -e "Failed to change Gateway. Please make sure dhcp is on the correct line.\nExiting Script."
						exit 1
					fi
				elif [[ $static_gw_confirm = n ]]; then
					echo "Please try again."
				else
					echo "not a valid answer. Please use \"y\" or \"n\"."
				fi
			done
		else
			echo "not a valid IP. Please enter a valid IP."
		fi
	done

echo -e "Network settings have been updated, and network has been refreshed.\nPlease connect using the new IP.\nExiting script."
systemctl restart networking
exit 1
}

# user input for server IP and Network
main_2_server_network() {
	echo -e "/nPlease choose the IP the server will use."
 	echo "NOTE: This will also be it's network. Make it different from your other networks."
  	echo "Example: 10.15.0.1 or 172.16.0.1. If you're not sure, just use one of these."
 	while true; do
   		read -p ": " server_network_input
     	if is_valid_ip "$server_network_input"; then
       		break
	  	else
    		echo "IP entered is not a valid IP. Please try again."
       	fi
	done
}

# user input for server port
main_2_server_port() {
	echo -e "/nPlease choose the Port number the server will use."
  	echo "NOTE: 51820 is what wireguard recommends. Use this if you are not sure."
	while true; do
   		read -p ": " server_port_input
     	if port_num_check "$server_port_input"; then
       		break
	  	else
    		echo "Port entered is not a valid port number. Please try again."
       	fi
	done
}

# Checks for necesarry programs
main_2_program_check() {
	check_install "systemd-resolved"
	check_install "iptables"
	check_install "openssh-client"
	check_install "openssh-server"
	check_install "openssh-sftp-server"
	check_install "wireguard"
}

main_2_DNS_input() {
# Asks for DNS input and pings DNS. Will ask re-input if DNS ping failed.
	while true; do
		echo -e "/nEnter a DNS for Resolved to use (input the gateway or firewall here)"
  		read -p ": " dns_ip
		if is_valid_ip "$dns_ip"; then
			echo "Valid IP address: $dns_ip"
			sed -i "/^#\?DNS=/c\DNS=$dns_ip" "$resolved_path"
			echo "Restarting systemd-resolved and checking DNS connection..."
   			systemctl restart systemd-resolved.service
			if ping -q -c 1 -w 1 "$dns_ip" &> /dev/null ; then
				echo "ping to "$dns_ip" was successful. Continuing with Installation..."
				break
			else
				echo "ping was unsuccessful, please try again."
			fi
		else
			echo "Invalid IP! Please enter a correct IP address (0.0.0.0 - 255.255.255.255)."
		fi
	done
}

main_2_wg_keygen() {
# checks to see if the private and public keys are generated.
	if [ ! -f /etc/wireguard/private.key ]; then
		umask 077 && wg genkey > /etc/wireguard/private.key
	fi
	if [ ! -f /etc/wireguard/public.key ]; then
		wg pubkey < /etc/wireguard/private.key > /etc/wireguard/public.key
	fi
# stores the private and public keys in variables for later use.
	private_key=$(cat /etc/wireguard/private.key)
	public_key=$(cat /etc/wireguard/public.key)
# Exports the varibles to be used ouside of the script
	echo "export private_key=$private_key" >> ~/.bashrc
	echo "export public_key=$public_key" >> ~/.bashrc
}

main_2_server_config() {
# Checks and makes the config folder
	if [ -f "$config_path" ]; then
		cat <<EOF > "$config_path"
[Interface]
PrivateKey = $private_key
Address = $server_network_input/32
ListenPort = $server_port_input

# IP forwarding
PreUp = sysctl -w net.ipv4.ip_forward=1

# This makes the server act as a router on the network.
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o $interf -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o $interf -j MASQUERADE
EOF
	fi
}

# Enables the Wireguard port as a service to start on boot.
main_2_enable_wg() {
	systemctl enable wg-quick@"$wg_port_name".service \
	&& systemctl daemon-reload \
	&& systemctl start wg-quick@wg0
	echo "The Wireguard Server installation has been completed!"
 }


###################
# Start of script #
###################

while true; do
	main_menu
 	case "$install_type" in
  		1)
			main_1_DHCP_check
			main_1_static_ip_edit
			main_1_cidr_edit
   			main_1_gateway_edit
		;;
  		2)
			config_file_check || continue
   			run_apt_update
   			main_2_program_check
			main_2_DNS_input
	  		config_file_creation
			main_2_server_network
			main_2_server_port
   			main_2_wg_keygen
	  		main_2_server_config
			main_2_enable_wg
   			print_public_key
		;;
  		3)
		;;
  		4)
		;;
		5)
  		;;
		6)
  		;;
		7)
  		;;
		exit)
  			echo "Exiting Script..."
	 		break
		;;
  		*)
			echo "Invalid Option. Please try again."
   		;;
	esac
done
