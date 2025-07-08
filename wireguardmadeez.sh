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
config_files=/etc/wireguard/*.conf

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

# Spinner display
spin() {
  local i=0
  local sp='|/-\\'
  local n=${#sp}
  printf ' '
  trap 'printf "\b \b"; exit' INT TERM EXIT
  while sleep 0.1; do
    printf '\b%s' "${sp:i++%n:1}"
  done
}


# Runs an apt update on the system to pull the latest applications.
run_apt_update() {
	echo "Starting apt update..."
	export DEBIAN_FRONTEND=noninteractive
	spin &
	spinpid=$!
	apt update &> /dev/null
  	kill "$spinpid"
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

# Reusable input validation.
check_user_input() {
	local prompt="$1"
 	local var_name="$2"
  	local validation_func="$3"
	while true; do
 		read -p "$prompt" user_input
		if ! "$validation_func" "$user_input"; then
  			echo "'$input' is not valid"
	 	else
   			eval "$var_name=\"\$user_input\""
	  		break
	 	fi
	 done
}

# Check for only letters and numbers.
alphanumeric_check() {
	[[ $1 ~= ^[[:alnum]]+$ ]]
}

# Check if user entered IP is valid
is_valid_ip() {
	local ip=$1
	local IFS='.'
	local -a octets=($ip)
	[[ "${octets[0]}" -eq 127 ]] && return 1
	[[ ${#octets[@]} -ne 4 ]] && return 1
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

# Check user inputted port number
port_num_check() {
	local num="$1"
	[[ ! $num =~ ^[1-9][0-9]*$ ]] && return 1
	(( num < 1 || num > 65535 )) && return 1

	return 0
}

# User config file choice
choosing_config() {
	unset config_choice_final
 	unset config_basename
 	config_files_array=(/etc/wireguard/*.conf)
	echo "Available config files:"
	local i=1
	for file in "${config_files_array[@]}"; do
		echo "$i) $file"
		((i++))
	done
	echo -e "\nPlease choose a config file to edit by number."
	while true; do
		read -p ": " config_choice
   		if [[ "$config_choice" =~ ^[0-9]+$ && "$config_choice" -ge 1 && "$config_choice" -le "${#config_files_array[@]}" ]]; then
			config_choice_final="${config_files_array[$config_choice -1]}"
   			config_basename="$(basename "$config_choice_final" .conf)"
			echo "You chose: $config_choice_final"
			break
		else
			echo "Invalid choice. Please enter a number between 1 and ${#[@]}."
		fi
   	done
}


# User input for config name
config_file_creation() {
	echo -e "\nName your Wireguard Port. This will be used for the config file name."
 	echo "EXAMPLE: server, wg0, wg1, wg2, etc."
  	while true; do
		read -p ": " wg_port_name
		if alphanumeric_check "$wg_port_name"; then
   			touch /etc/wireguard/"$wg_port_name".conf
			config_path="/etc/wireguard/${wg_port_name}.conf"
   			return 1
   		else
	 		echo "Not a valid input. Must be an alphanumeric input."
		fi
  	done
}

# checks to see if there is a wireguard config, then stops the setup.
config_file_check() {
	if ! compgen -G "$config_files"; then
		echo " **WARNING** Wireguard config file not found, please run either the Wireguard Server or Wireguard Peer setup."
		return 1
	fi
 }

# checks to see if the config file is set up to be a peer. If it is, it will tell the user.
config_file_check_peer() {
	if grep -q '^Endpoint' $config_choice_final; then
		echo -e "\n **WARNING** This config file is set up to be a Peer. Please run the \"Client Peer Config\" option instead."
		break
	fi
}

wg_keygen() {
	# 
	umask 077 && wg genkey > /etc/wireguard/"$wg_port_name"_private.key
	wg pubkey < /etc/wireguard/private.key > /etc/wireguard/"$wg_port_name"_public.key
	# 
	"$wg_port_name"_private_key=$(cat /etc/wireguard/"$wg_port_name"_private.key)
	"$wg_port_name"_public_key=$(cat /etc/wireguard/"$wg_port_name"_public.key)
	# 

	if ! grep -q 'private_key=' ~/.bashrc; then
		printf 'export private_key="%s"\n' "$private_key" >> ~/.bashrc
	fi

	if ! grep -q 'public_key=' ~/.bashrc; then
    	printf 'export public_key="%s"\n' "$public_key" >> ~/.bashrc
	fi
}

# print the public key for the user to use in clients.
print_public_key_set_aliases() {
	echo -e "\nPrinting the Public key\n\n$public_key\n\n"
	echo "Please copy this key to use for setting up the client"
 	echo "Aliases are set. Manually run ~/.bashrc or open a new terminal to use them." 
 	
	start_name="${wg_port_name}start"
	start_line="alias ${start_name}=\"systemctl start wg-quick@${wg_port_name}\""
	sed -i "/^alias ${start_name}=/d" ~/.bashrc
	printf '%s\n' "$start_line" >> ~/.bashrc

	stop_name="${wg_port_name}stop"
	stop_line="alias ${stop_name}=\"systemctl stop wg-quick@${wg_port_name}\""
	sed -i "/^alias ${stop_name}=/d" ~/.bashrc
	printf '%s\n' "$stop_line" >> ~/.bashrc

 	status_name="${wg_port_name}status"
	status_line="alias ${status_name}=\"systemctl status wg-quick@${wg_port_name}\""
	sed -i "/^alias ${status_name}=/d" ~/.bashrc
	printf '%s\n' "$status_line" >> ~/.bashrc

	restart_name="${wg_port_name}restart"
 	restart_line="alias ${restart_name}=\"systemctl restart wg-quick@${wg_port_name}\""
  	sed -i "/^alias ${restart_name}=/d" ~/.bashrc
	printf '%s\n' "$restart_line" >> ~/.bashrc
}

# Shows the Peers that are on the server.
server_peer_show() {
	echo -e "\nHere are the list of Peers currently configured:\n"
	awk -F' = |# ' '/#/{name=$2} /AllowedIPs/{print name, $2}' "$config_choice_final"
}

# Exit to the previous menu
exit_selection() {
	echo "Exiting..."
}

invalid_option() {
	echo "Invalid option. Please try again."
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

Type "exit" (or ctrl + c) to exit the script.
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

# Asks for DNS input and pings DNS. Will ask re-input if DNS ping failed. Also installs programs needed for Server.
main_2_DNS_input_program_check() {
	spin &
  	spinpid=$!
	check_install "wireguard"
  	check_install "iptables"
	check_install "openssh-client"
	check_install "openssh-server"
	check_install "openssh-sftp-server"
 	check_install "systemd-resolved"
  	kill "$spinpid"
 	while true; do
		echo -e "\nEnter a DNS for Resolved to use (input the gateway or firewall here)"
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

# user input for server IP and Network
main_2_server_network() {
	echo -e "\nPlease choose the IP the server will use."
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
	echo -e "\nPlease choose the Port number the server will use."
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

# Checks and makes the config folder
main_2_server_config() {
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
	&& systemctl start wg-quick@"$wg_port_name"
	echo "The Wireguard Server installation has been completed!"
 }

# Peer selection menu.
main_3_selection_submenu() {
	echo -e "\nServer Peer Configuration"
	read -p $'\n1. Add a new Peer.\n2. Remove a Peer.\n3. Edit a Peer.\n4. Exit back to the main menu\n: ' peer_choice
}

# Adds a peer to a server config.
sub_3.1_peer_config() {
	cat <<EOF >> "$config_choice_final"
[Peer]
# $peer_name
PublicKey = $peer_key
AllowedIPs = $peer_ip/32
EOF
	echo "Peer added successfully. Restarting Wireguard..." \
	&& systemctl restart wg-quick@$config_basename.service
}

###################
# Start of script #
###################

while true; do
	main_menu
 	case "$install_type" in
  		1)  # Set static IP
			main_1_DHCP_check
			main_1_static_ip_edit
			main_1_cidr_edit
   			main_1_gateway_edit
		;;
  		2)  # Server Install
			
   			run_apt_update
			main_2_DNS_input_program_check
			config_file_creation
   			# wg_keygen
			main_2_server_network
			main_2_server_port
	  		main_2_server_config
			main_2_enable_wg
   			print_public_key_set_aliases
		;;
  		3)  # Server Peer editing.
			while true; do
   				config_file_check || continue
	   			choosing_config
	   			config_file_check_peer
	   			server_peer_show
	   			main_3_selection_submenu
	   			case "$peer_choice" in
	   				1) # Add a Peer
						server_peer_show
	  					read -p $'\nEnter a name for the peer\n: ' peer_name
	  					check_user_input $'Enter the IP for the peer to use\n: ' peer_ip is_valid_ip
						check_user_input $'Enter the public key from the client peer\n: ' peer_key key_check
	  					sub_3.1_peer_config && break
					;;
					2)
	 				;;
	 				3)
	  				;;
	  				4) # Exit
	   					exit_selection && break
		 			;;
		 			*)
	  					invalid_option
		 			;;
		 		esac
       		done
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
  			exit_selection && break
		;;
  		*)
			invalid_option
   		;;
	esac
done
