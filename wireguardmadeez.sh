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
config_files=/etc/wireguard/*.conf

interf=$(grep '^\s*iface\s\+\w\+\s\+inet\s\+static' /etc/network/interfaces | awk '{print $2}')

NC=$'\e[0m'
RED=$'\e[0;31m'
CYAN=$'\e[0;36m'
GREEN=$'\e[0;32m'
YELLOW=$'\e[0;33m'

alphanumeric_type="input. Only alphanumeric characters allowed."
ip_type="ip."
cidr_type="cidr. Only 0-32 allowed."
key_type="key."
port_type="port number. Only 49152-65535 may be used."

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
			echo -e "${RED}Installation failed. Please clear the error and try again.${NC}"
			exit 1
		fi
	else
		echo -e "${GREEN}$install_name is already installed. Continuing...${NC}"
	fi
}

# Reusable input validation.
check_user_input() {
	local prompt="$1"
 	local var_name="$2"
  	local validation_func="$3"
	local type="$4"
	while true; do
 		read -p "$prompt" user_input
		if ! "$validation_func" "$user_input"; then
  			echo -e "${RED}'${user_input}' is not a valid ${type}${NC} Please try again."
	 	else
   			eval "$var_name=\"\$user_input\""
	  		return
	 	fi
	done
}

check_user_input_space() {
	local prompt="$1"
 	local var_name="$2"
  	local validation_func="$3"
	local type="$4"
	while true; do
 		read -p "$prompt" user_input
		if [[ -z "$user_input" ]]; then
			echo "Returning to previous menu."
			return 1
		elif ! "$validation_func" "$user_input"; then
  			echo -e "${RED}'${user_input}' is not a valid ${type}${NC} Please Try again."
	 	else
   			eval "$var_name=\"\$user_input\""
	  		return
	 	fi
	done
}

check_user_input_y_N() {
 	local prompt="$1"
	while true; do
		read -p "$prompt" user_input
		user_input="${user_input,,}"  # convert to lowercase
		if [[ -z "$user_input" || "$user_input" == "n" ]]; then
			echo "Returning to previous menu."
			return 1
		elif [[ "$user_input" == "y" ]]; then
			return
		else
			echo "Invalid input. Please enter 'y' or 'n'."
		fi
	done
}

check_user_input_Y_n() {
 	local prompt="$1"
	while true; do
		read -p "$prompt" user_input
		user_input="${user_input,,}"  # convert to lowercase
		if [[ -z "$user_input" || "$user_input" == "y" ]]; then
			return
		elif [[ "$user_input" == "n" ]]; then
			return 1
		else
			echo "Invalid input. Please enter 'y' or 'n'."
		fi
	done
}

check_user_input_select() {
 	local input_one="$1"
		if grep -q "# $input_one" "$config_choice_final"; then
			return
		else
			echo -e "${RED}User not found, please try again.${NC}"
			return 1
		fi
}

# Check for only letters and numbers.
alphanumeric_check() {
	[[ $1 =~ ^[[:alnum:]_]+$ ]]
}

# Check if user entered IP is valid
valid_ip_check() {
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
	[[ "$key" =~ ^[A-Za-z0-9+/]{43}=$ ]]
}

# Check user inputted port number
port_num_check() {
	local num="$1"
	[[ ! $num =~ ^[1-9][0-9]*$ ]] && return 1
	(( num < 49152 || num > 65535 )) && return 1

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
		echo -e "${GREEN}$i) $file${NC}"
		((i++))
	done
	echo -e "\nPlease choose a config file to edit by number. (Press enter to return to main menu.)"
	while true; do
		read -p ": " config_choice
		if [[ -z "$config_choice" ]]; then
			echo "Returning to previous menu."
			return 1
   		elif [[ "$config_choice" =~ ^[0-9]+$ && "$config_choice" -ge 1 && "$config_choice" -le "${#config_files_array[@]}" ]]; then
			config_choice_final="${config_files_array[$config_choice -1]}"
   			config_basename="$(basename "$config_choice_final" .conf)"
			echo -e "${GREEN}You chose: $config_choice_final${NC}"
			break
		else
			echo -e "${RED}Invalid choice. Please enter a number between 1 and ${#config_files_array[@]}. ${NC}"
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
			config_path="/etc/wireguard/${wg_port_name}.conf"
			if [[ ! -f "$config_path" ]]; then
   				touch /etc/wireguard/"$wg_port_name".conf
   				return 0
			else
				echo -e "${RED}File name already in use, please remove file from /etc/wireguard or choose another name for the Wireguard Port.${NC}"
			fi
   		else
	 		echo -e "${RED}Not a valid input. Must be an alphanumeric input.${NC}"
		fi
  	done
}

# checks to see if there is a wireguard config, then stops the setup.
config_file_check() {
	if ! compgen -G "$config_files" > /dev/null; then
		echo -e " ${RED}**WARNING**${NC} Wireguard config file not found, please run either the Wireguard Server or Wireguard Peer setup."
		return 1
	fi
 }

# checks to see if the config file is set up to be a peer. If it is, it will tell the user.
config_file_check_peer() {
	if grep -q '^Endpoint' $config_choice_final; then
		echo -e "\n ${RED}**ERROR**${NC} This config file is set up to be a Peer. Please try again."
		return 1
	fi
}

# Checks to see if the config file is set up to be a server. If it is, it will tell the user.
config_file_check_server() {
	if grep -q '^ListenPort' $config_choice_final; then
		echo -e "\n ${RED}**WARNING**${NC} This config file is set up to be a Server. Please try again."
		return 1
	fi
}

# Checks to make sure there isn't another input of the same in the config file.
unique() {
	local var_name="$1"
	if grep -q "$var_name" "$config_choice_final"; then
		echo -e "${RED}ERROR${NC}"
		echo "Douplicate input detected. ${var_name} is in use by another user. Please try again."
		return 1
	fi
}

wg_keygen() {
	umask 077 && wg genkey > /etc/wireguard/"$wg_port_name"_private.key
	wg pubkey < /etc/wireguard/"$wg_port_name"_private.key > /etc/wireguard/"$wg_port_name"_public.key

	unset private_key
	unset public_key
	private_key=$(< /etc/wireguard/"$wg_port_name"_private.key)
	public_key=$(< /etc/wireguard/"$wg_port_name"_public.key)

	eval "${wg_port_name}_private_key=\"\$private_key\""
	eval "${wg_port_name}_public_key=\"\$public_key\""

	sed -i "/^export ${wg_port_name}_private_key=/d" ~/.bashrc
	printf 'export %s="%s"\n' "${wg_port_name}_private_key" "$(cat /etc/wireguard/"$wg_port_name"_private.key)" >> ~/.bashrc

	sed -i "/^export ${wg_port_name}_public_key=/d" ~/.bashrc
	printf 'export %s="%s"\n' "${wg_port_name}_public_key" "$(cat /etc/wireguard/"$wg_port_name"_public.key)" >> ~/.bashrc
	 
}

# print the public key for the user to use in clients.
print_public_key_set_aliases() {
	echo -e "\nPrinting the Public key\n\n${GREEN}$public_key${NC}\n\n"
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
	awk -F' = |# ' -v cyan="$CYAN" -v nc="$NC" '
    		/#/{name=$2}
		/PublicKey/{public=$2}
		/AllowedIPs/{
        printf "%s%s%s %s\n", cyan, name, nc, $2
        print "PublicKey:", public "\n"
	}
	' "$config_choice_final"
}

# Enables the Wireguard port as a service to start on boot.
enable_wg() {
	echo "Enabling the port to start on boot..."
	systemctl enable wg-quick@"$wg_port_name".service \
	&& systemctl daemon-reload \
	&& systemctl start wg-quick@"$wg_port_name"
	echo -e "${GREEN}The Wireguard installation has been completed!${NC}"
}

# Exit to the previous menu
exit_selection() {
	echo "Exiting..."
}

invalid_option() {
	echo -e "${RED}Invalid option. Please try again.${NC}"
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
	echo "Editing network config file for static deployment"
	if grep -q dhcp $net_interf; then
		sed -i 's/dhcp/static/' $net_interf \
		&& echo -e "        address\n        gateway" >> $net_interf
	fi
}

# Edits the IP (Only the IP)
main_1_static_ip_edit() {
	echo -e "${RED}\n***WARNING***\nOnce you change the IP, you WILL be disconnected.\nYou will need to re-connect using the correct IP.${NC}\n"
	check_user_input $'Input the static IP you would like the Wireguard Server to use. (e.g. 192.168.1.2)\n: ' static_ip valid_ip_check "$ip_type" || return 1
	check_user_input_Y_n  "Are you sure you want to use ${static_ip}? (Y/n)" || return 1
	sed -i "/address/c\        address "$static_ip" " $net_interf \
	&& echo "Address has been changed."	
}

# Adds the CIDR notation to the end of the user inputed static IP.
main_1_cidr_edit() {
	check_user_input $'Enter the subnet in CIDR notation. (e.g. 24)\n: ' cidr_input cidr_check "$cidr_type" || return 1
	check_user_input_Y_n "Are you sure you want to use $cidr_input? (Y/n)" || return 1
	sed -i "/"$static_ip"/c\        address "$static_ip"\/"$cidr_input" " $net_interf \
	&& echo "Subnet has been added."
}

# Edits the gateway for static IP
main_1_gateway_edit() {
	check_user_input $'Input the gateway\n: ' static_gw valid_ip_check "$ip_type" || return 1
	check_user_input_Y_n "Are you sure you want to use $static_gw? (Y/n)" || return 1
	sed -i "/gateway/c\        gateway "$static_gw" " $net_interf \
	&& echo -e "${GREEN}Gateway has been changed.${NC}"
}

main_1_apply_network() {
	echo -e "${GREEN}Network settings have been updated, and network has been refreshed.\nPlease connect using the new IP.\nExiting script.${NC}"
	systemctl restart networking
	exit 1
}

main_2_file_check_server() {
    shopt -s nullglob
    config_files_array=(/etc/wireguard/*.conf)
    if ((${#config_files_array[@]} > 0)); then
        for config_file in "${config_files_array[@]}"; do
            if grep -q '^ListenPort' "$config_file"; then
                echo -e "${RED}There is already a server configuration file configured. Please run Option 3, Server Peer Config.${NC}"
                return 1
            fi
        done
    else
        echo -e "${GREEN}There are no server configuration files found. Continuing...${NC}"
    fi

	shopt -u nullglob
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
		check_user_input $'\nEnter a DNS for Resolved to use. (The gateway or firewall IP would be best.)\n: ' dns_ip valid_ip_check "$ip_type" || break
		echo "Valid IP address: $dns_ip"
		sed -i "/^#\?DNS=/c\DNS=$dns_ip" "$resolved_path"
		echo "Restarting systemd-resolved and checking DNS connection..."
		systemctl restart systemd-resolved.service
		if ping -q -c 1 -w 1 "$dns_ip" &> /dev/null ; then
			echo -e "${GREEN}ping to "$dns_ip" was successful. Continuing with Installation...${NC}"
			break
		else
			echo -e "${RED}ping was unsuccessful, please try again.${NC}"
		fi
	done
}

# user input for server IP and Network
main_2_server_network() {
	echo -e "\nPlease choose the IP the server will use."
 	echo -e "${YELLOW}NOTE: This will also be it's network. Make it different from your other networks.${NC}"
  	echo "${YELLO}Example: 10.15.0.1 or 172.16.0.1. If you're not sure, just use one of these.${NC}"
 	check_user_input ": " server_network_input valid_ip_check "$ip_type"
}

# user input for server port
main_2_server_port() {
	echo -e "\nPlease choose the Port number the server will use."
  	echo "NOTE: 51820 is what wireguard recommends. Use this if you are not sure."
	check_user_input ": " server_port_input port_num_check "$port_type"
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

# Peer selection menu.
main_3_selection_submenu() {
	echo
	cat << EOF

Server Peer Configuration

1. Add a new Peer.
2. Remove a Peer.
3. Edit a Peer.
4. Exit back to the main menu.
EOF

	read -p ": " peer_choice
}

# Adds a peer to the server config.
sub_3.1_peer_config() {
	cat <<EOF >> "$config_choice_final"
[Peer]
# $peer_name
PublicKey = $peer_key
AllowedIPs = $peer_ip/32
EOF
	echo -e "${GREEN}Peer added successfully. Restarting Wireguard...${NC}" \
	&& systemctl restart wg-quick@$config_basename.service
}

# Deletes a peer from the server config.
sub_3.2_delete() {
	echo "Which user would you like to delete?"
	echo "\n(${YELLOW}NOTE:${NC} Name only. Case sensitive. Leave blank to return to previous menu)\n"
	read -p $': ' user_select
	if [[ -z "$user_select" ]]; then
		echo "Returning to previous menu."
		break
	elif grep -q "# $user_select" "$config_choice_final"; then
		sed -i "/\[Peer\]/ { N; /\n# $user_select/ { N; N; d; } }" "$config_choice_final"
		sed -i '/^$/N;/^\n$/D' "$config_choice_final"
		echo -e "${RED}User '$user_select' deleted.${NC}" \
		&& systemctl restart wg-quick@${config_basename}.service
	else
		echo -e "${RED}User not found, please try again.${NC}"
		return 1
	fi
}

# sub_3.2_peer_delete() {
#	sed -i "/\[Peer\]/ { N; /\n# $user_select/ { N; N; d; } }" "$config_choice_final" \
#	&& sed -i '/^$/N;/^\n$/D' "$config_choice_final" \
#	&& echo -e "${RED}User '$user_select' deleted.${NC}" \
#	&& systemctl restart wg-quick@${config_basename}.service
#}

sub_3.3_user_select() {
	echo -e "Which user would you like to edit? (${YELLOW}NOTE:${NC} Name only. Case sensitive. Leave blank to return to previous menu)\n"
	read -p $': ' user_select_3_3
	if ! grep -q "# $user_select_3_3" "$config_choice_final"; then
		echo -e "${RED}User not found. Please try again.${NC}"
		return 1
	elif [[ -z "$user_select_3_3" ]]; then
		return 1
	fi
}

sub_3.3_menu() {
	echo
	cat << EOF
Which setting would you like to edit?

1. Change the Public Key.
2. Change the user's IP.

Type 'Exit' to go back to the previous menu.
EOF

	read -p ": " setting_select_3_3
}

sub_3.3.1_change_public_key() {
	check_user_input $'Please enter the New Public Key you would like to use\n: ' new_public_key key_check "$ip_type" \
	&& sed -i "/# $user_select_3_3/,/^\[Peer\]/ { s|^PublicKey =.*|PublicKey = ${new_public_key}| }" "$config_choice_final" \
	&& echo -e "${GREEN}Public Key has been changed. Restarting Wireguard...${NC}" \
	&& systemctl restart wg-quick@${config_basename}.service
}

sub_3.3.2_change_ip() {
	check_user_input $'Please enter the new IP you would like to use\n: ' new_ip valid_ip_check "$ip_type" \
	&& sed -i "/# $user_select_3_3/,/^\[Peer\]/ { s/^AllowedIPs =.*/AllowedIPs = ${new_ip}\/32/ }" "$config_choice_final" \
	&& echo -e "${GREEN}The IP has been changed. Restarting Wireguard...${NC}" \
	&& systemctl restart wg-quick@${config_basename}.service
}

main_4_collect_networks_loop() {
	local ip_list=()
	while true; do
		check_user_input $'Please enter the Allowed Network(s). (Note: 0.0.0.0 is full tunnel. Please use a 0 in the 4th octet)\n: ' allowed_ips_peer valid_ip_check "$ip_type"
		check_user_input $'Please enter the CIDR of your Allowed Network\n: ' allowed_ip_cidr cidr_check "$cidr_type"
		ip_list+=("$allowed_ips_peer"/"$allowed_ip_cidr")
		check_user_input_y_N $'Would you like to add another Allowed Network? (y/N): ' || break
	done
	collected_ips=$(IFS=, ; echo "${ip_list[*]}")
}

main_4_peer_config() {
	if [ -f "$config_path" ]; then   
		cat <<EOF > "$config_path"
[Interface]
PrivateKey = $private_key
Address = $peer_address/32

[Peer]
# Wireguard VM server on local Proxmox
PublicKey = $peer_pk
AllowedIPs = $collected_ips
Endpoint = $endpoint_address:$port_num
EOF
	fi
}

main_5_menu() {
	echo
	cat << EOF
Which setting would you like to edit?

1. Edit the peer address.
2. Edit the remote Wireguard Public Key.
3. Edit Allowed Networks.
4. Edit the IP and Port of the Endpoint. (The server this peer is connecting to).

Type 'Exit' to go back to the previous menu.
EOF

	read -p ": " setting_select_5
}

sub_5.1_edit_ip() {
	echo -e "\nHere is the IP for this connection:"
	grep '^Address' "$config_choice_final"
	check_user_input $'\nPlease enter the new IP you would like to use\n: ' new_peer_ip valid_ip_check "$ip_type" \
	&& sed -i "/^Address =/c\Address = $new_peer_ip" "$config_choice_final" \
	&& echo -e "${GREEN}The IP has been changed. Restarting Wireguard...${NC}" \
	&& systemctl restart wg-quick@${config_basename}.service
}

sub_5.2_edit_public_key() {
	echo -e "\nHere is the Public Key for the Remote Wireguard Server:\n"
	grep '^PublicKey' "$config_choice_final"
	check_user_input $'\nPlease enter the new Public Key\n: ' new_peer_public_key "$key_type"
	sed -i "/^PublicKey =/c\PublicKey = $new_peer_public_key" "$config_choice_final" \
	&& echo -e "${GREEN}The Public Key has been changed. Restarting Wireguard...${NC}" \
	&& systemctl restart wg-quick@${config_basename}.service
}
###################
# Start of script #
###################

while true; do
	main_menu
 	case "$install_type" in
  		1)  # Set static IP
			while true; do
				main_1_DHCP_check || continue
				main_1_static_ip_edit || continue
				main_1_cidr_edit || continue
   				main_1_gateway_edit || continue
				break
			done
			main_1_apply_network
		;;
  		2)  # Server Install
			main_2_file_check_server || continue
   			run_apt_update
			main_2_DNS_input_program_check
			config_file_creation
   			wg_keygen
			main_2_server_network
			main_2_server_port
	  		main_2_server_config
			enable_wg
   			print_public_key_set_aliases
		;;
  		3)  # Server Peer editing.
			while true; do
   				config_file_check || continue
	   			choosing_config || break
	   			config_file_check_peer || continue
	   			server_peer_show
	   			main_3_selection_submenu
	   			case "$peer_choice" in
	   				1) # Add a Peer
						while true; do
							server_peer_show
	  						check_user_input $'\nEnter a name for the peer\n: ' peer_name alphanumeric_check "$alphanumeric_type"
							unique "$peer_name" || continue
	  						check_user_input_space $'Enter the IP for the peer to use\n: ' peer_ip valid_ip_check "$ip_type"
							unique "$peer_ip" || continue
							check_user_input_space $'Enter the public key from the client peer\n: ' peer_key key_check "$key_type"
							unique "$peer_key" || continue
							break
	  					done
						sub_3.1_peer_config && break
					;;
					2) # Delete a Peer
						server_peer_show
						sub_3.2_delete
						# sub_3.2_peer_delete && break
	 				;;
	 				3)
						server_peer_show
						while true; do
							sub_3.3_user_select || break
							sub_3.3_menu
							case "$setting_select_3_3" in
								1)
									sub_3.3.1_change_public_key && break
								;;
								2)
									sub_3.3.2_change_ip && break
								;;
								exit)
									exit_selection && break
								;;
								*)
									invalid_option
								;;
							esac
						done
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
  		4) # installs a wireguard port.
			run_apt_update
			check_install "wireguard"
			config_file_creation
			wg_keygen
			check_user_input $'Please enter the IP Address for this Peer\n: ' peer_address valid_ip_check "$ip_type"
			check_user_input $'Please enter the Public Key of the Remote Wireguard Server this peer will connect to\n: ' peer_pk key_check "$key_type"
			main_4_collect_networks_loop
			check_user_input $'Please enter the Endpoint IP of the Wireguard server this peer will connect to (LAN for inside networ, WAN for outside)\n: ' endpoint_address valid_ip_check "$ip_type"
			check_user_input $'Please enter the Port number the Wiregard Server is using\n(Default port is 51820): ' port_num port_num_check "$port_type"
			main_4_peer_config
			print_public_key_set_aliases
			enable_wg
		;;
		5) # Client Peer Config.
			#_check
			choosing_config
			config_file_check_server
			main_5_menu
			case "$setting_select_5" in
				1) # Edits the IP Address of the Peer Config.
					sub_5.1_edit_ip
				;;
				2) # Edits the Public Key of the Remote Wireguard Server this peer is connecting to.
					sub_5.2_edit_public_key
				;;
				3)
				;;
			esac
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
