#!/bin/bash

########################################################################################################################################################################################
# Copy the line below to download and run:                                                                                                                                             #
# wget -O wireguardmadeez.sh https://raw.githubusercontent.com/chuckmcilrath/WireguardMadeEZ/refs/heads/main/wireguardmadeez.sh && chmod +x wireguardmadeez.sh && ./wireguardmadeez.sh #
#                                                                                                                                                                                      #
########################################################################################################################################################################################

####################
# GLOBAL VARIABLES #
####################

# paths to folders.
resolved_path=/etc/systemd/resolved.conf
net_interf=/etc/network/interfaces
config_files=/etc/wireguard/*.conf

# finds the interface for use in a config file.
interf=$(grep '^\s*iface\s\+\w\+\s\+inet\s\+\(static\|dhcp\)' /etc/network/interfaces | awk '{print $2}')

# ANSI color codes.
NC=$'\e[0m'
RED=$'\e[0;31m'
CYAN=$'\e[0;36m'
GREEN=$'\e[0;32m'
YELLOW=$'\e[0;33m'

# Used in functions to specify what failed.
alphanumeric_type="input. Only alphanumeric characters allowed."
ip_type="ip."
cidr_type="cidr. Only 0-32 allowed."
key_type="key."
port_type="port number. Only 49152-65535 may be used."
multi_type="ip or ddns."

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
  while true; do
    printf '\r%s ' "${sp:i++%n:1}"
    sleep 0.1
  done
}

# Runs an apt update on the system to pull the latest applications.
run_apt_update() {
	echo "Starting apt update..."
	export DEBIAN_FRONTEND=noninteractive
	spin &
	spinpid=$!
	apt update &> /dev/null
  	kill "$spinpid" 2>/dev/null
  	wait "$spinpid" 2>/dev/null
  	printf '\r \r'  # Clear the spinner
  	echo "Apt update has been completed."
}

# Check to see if an app is installed.
check_install() {
	local install_name="$1"
	printf '\r \r'  # Clear any spinner character
	echo "looking for $install_name..."
	if ! dpkg -l | awk '{print $2}' | grep -xq "$install_name"; then
		printf '\r \r'  # Clear spinner before printing
		echo "Installing $install_name..."
		apt install $install_name -y &> /dev/null
		if dpkg -l | awk '{print $2}' | grep -xq "$install_name"; then
			printf '\r \r'  # Clear spinner before printing
			echo "$install_name has been successfully installed."
		else
			printf '\r \r'  # Clear spinner before printing
			echo -e "${RED}Installation failed. Please clear the error and try again.${NC}"
			exit 1
		fi
	else
		printf '\r \r'  # Clear spinner before printing
		echo -e "${GREEN}$install_name is already installed. Continuing...${NC}"
	fi
}

# Reusable input validation.
check_input_validate() {
	local prompt="$1"
 	local var_name="$2"
  	local validation_func="$3"
	local type="$4"
	local user_input
	while true; do
 		read -rp "$prompt" user_input
		if ! "$validation_func" "$user_input"; then
  			echo -e "${RED}'${user_input}' is not a valid ${type}${NC} Please try again."
	 	else
   			eval "$var_name=\"\$user_input\""
	  		return 0
	 	fi
	done
}

check_input_validate_2() {
	local prompt="$1"
	local var_name="$2"
	local validation_func="$3"
	local validation_func_2="$4"
	local type="$5"
	local user_input
	while true; do
		read -rp "$prompt" user_input
		if ! "$validation_func" "$user_input" && ! "$validation_func_2" "$user_input"; then
			echo -e "${RED}'${user_input}' is not a valid ${type}${NC} Please try again."
		else
			eval "$var_name=\"\$user_input\""
			return 0
		fi
	done
}

check_input_validate_space() {
 	local prompt="$1"
 	local var_name="$2"
  	local validation_func="$3"
	local type="$4"
	local user_input
	while true; do
 		read -rp "$prompt" user_input
		if [[ -z "$user_input" ]]; then
			return 1
	 	elif ! "$validation_func" "$user_input"; then
  			echo -e "${RED}'${user_input}' is not a valid ${type}${NC} Please try again."
		else
   			eval "$var_name=\"\$user_input\""
	  		return 0
	 	fi
	done
}

check_user_input_y_N() {
 	local prompt="$1"
	while true; do
		read -rp "$prompt" user_input
		user_input="${user_input,,}"  # convert to lowercase
		if [[ -z "$user_input" || "$user_input" == "n" ]]; then
			return 1
		elif [[ "$user_input" == "y" ]]; then
			return 0
		else
			echo "Invalid input. Please enter 'y' or 'n'."
		fi
	done
}

check_user_input_Y_n() {
 	local prompt="$1"
	while true; do
		read -rp "$prompt" user_input
		user_input="${user_input,,}"  # convert to lowercase
		if [[ -z "$user_input" || "$user_input" == "y" ]]; then
			return 0
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
			return 0
		else
			echo -e "${RED}User not found, please try again.${NC}"
			return 1
		fi
}

# Check for only letters and numbers.
alphanumeric_check() {
	[[ $1 =~ ^[[:alnum:]_]+$ ]]
}

# DNS Check
DNS_check() {
	if ping -q -c 1 -w 1 google.com &> /dev/null; then
		echo -e "${GREEN}\nDNS is resolving, continuing with installation...${NC}\n"
	else
		echo -e "${RED}\nDNS is not resolving.\n${NC}"
		echo -e "${RED}WARNING!\n${NC}"
		if check_user_input_Y_n "This script will overwrite your /etc/resolv.conf file. Proceed? (Y/n):"; then
			while true; do
				check_input_validate $'\nEnter a DNS IP to use. (The gateway or firewall IP would be best.)\n: ' dns_ip valid_ip_check "$ip_type"
				echo "Valid IP address: $dns_ip. Updating DNS..."
				echo "nameserver $dns_ip" > /etc/resolv.conf
				if ping -q -c 1 -w 1 google.com &> /dev/null; then
					echo -e "${GREEN}DNS has been resolved${NC}, continuing with script..."
					return 1
				else
					echo -e "${RED}DNS update failed. retrying...${NC}"
				fi
			done
		else
			echo -e "${RED}\nExiting script. You will need to resolve your DNS before running the script again.${NC}\n"
			exit
		fi
	fi
}

# Check if user entered IP is valid
valid_ip_check() {
    local ip=$1
    local -a octets
    IFS='.' read -ra octets <<< "$ip"
    [[ ! "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && return 1
    [[ ${#octets[@]} -ne 4 ]] && return 1
    for octet in "${octets[@]}"; do
        [[ "$octet" =~ ^0[0-9]+$ ]] && return 1
        [[ ! "$octet" =~ ^[0-9]+$ ]] && return 1
        ((10#$octet < 0 || 10#$octet > 255)) && return 1
    done
    [[ "${octets[0]}" -eq 127 ]] && return 1
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

default_cidr_validate() {
	local prompt="$1"
 	local var_name="$2"
  	local validation_func="$3"
	local type="$4"
	local user_input
	echo -e "${YELLOW}NOTE:${NC} Leave empty to select ${CYAN}/24${NC}."
	while true; do
 		read -rp "$prompt" user_input
		if [[ -z "$user_input" ]]; then
			eval "$var_name"=24
			echo "Default of ${CYAN}/24${NC} has been selected."
			return 0
		elif ! "$validation_func" "$user_input"; then
  			echo -e "${RED}'${user_input}' is not a valid ${type}${NC} Please try again."
	 	else
   			eval "$var_name=\"\$user_input\""
	  		return 0
	 	fi
	done
}

default_port() {
	local = user_input
	echo -e "\nPlease enter the Port number."
  	echo -e "${YELLOW}NOTE:${NC} Press ENTER to use the default, 51820."
	while true; do
		read -rp ": " user_input
		if [[ -z "$user_input" ]]; then
			port_num="51820"
			return 0
		elif [[ -n "$user_input" ]]; then
    		if port_num_check "$user_input"; then
				port_num="$user_input"
				return 0
    		else
        		echo -e "${RED}'${user_input}' is not a valid ${port_type}${NC} Please try again."
    		fi
		fi
	done
}

valid_ddns_check() {
	local name="$1"
	[[ "$name" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && return 1
	(( ${#name} > 253 )) && return 1
	IFS='.' read -ra labels <<< "$name"
	for label in "${labels[@]}"; do
		[[ -z "$label" ]] && return 1
		(( ${#label} > 63 )) && return 1
		[[ ! "$label" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$ ]] && return 1
	done
	return 0
}

# Check if no configs exist or
config_file_check() {
	shopt -s nullglob
	config_files_array=(/etc/wireguard/*.conf)

	if [[ ! -e "${config_files_array[0]}" ]]; then
		echo -e "\n${RED}ERROR:${NC} No configuration found!"
		return 1
	fi
	shopt -u nullglob
}

# User config file choice
choosing_config() {
	shopt -s nullglob
	unset config_choice_final
	unset config_basename
	config_files_array=(/etc/wireguard/*.conf)

	if [[ ${#config_files_array[@]} -eq 1 ]]; then 
		config_choice_final="${config_files_array[0]}"
		config_basename="$(basename "$config_choice_final" .conf)"
		echo -e "\n1 config available.${GREEN} ${config_basename} ${NC}was selected."
		return 0
	else
		echo -e "\nAvailable config files:"
		local i=1
		for file in "${config_files_array[@]}"; do
			echo -e "${GREEN}$i) ${file##*/}${NC}"
			((i++))
		done
		echo -e "\nPlease choose a config file. (Press ENTER to return to previous menu.)"
		while true; do
			read -rp ": " config_choice
			if [[ -z "$config_choice" ]]; then
				echo "Returning to previous menu."
				return 1
			elif [[ "$config_choice" =~ ^[0-9]+$ && "$config_choice" -ge 1 && "$config_choice" -le "${#config_files_array[@]}" ]]; then
				config_choice_final="${config_files_array[$config_choice -1]}"
				config_basename="$(basename "$config_choice_final" .conf)"
				echo -e "\n${GREEN}You chose: $config_choice_final${NC}"
				return 0
			else
				echo -e "${RED}Invalid choice. Please enter a number between 1 and ${#config_files_array[@]}.${NC}"
			fi
		done
	fi
	shopt -u nullglob
}


# User input for config name
config_file_creation() {
  	config_files_array=(/etc/wireguard/*.conf)
	while true; do
		if [[ ! -e "${config_files_array[0]}" ]]; then
			echo -e "\nNo configuration(s) found on this device."
		else
			echo -e "\nHere is a list of ${CYAN}Interfaces${NC} found on this device:"
			for file in "${config_files_array[@]}"; do
				echo -e "${GREEN}${file##*/}${NC}"
			done
		fi
		echo -e "\nName your Wireguard ${GREEN}Interface${NC}. This will be used for the config file name. Leave blank to return to main menu."
 		echo -e "${YELLOW}EXAMPLE:${NC} server, dcm, wg0, wg1, etc."
		read -rp ": " wg_port_name
		if alphanumeric_check "$wg_port_name"; then
			config_path="/etc/wireguard/${wg_port_name}.conf"
			if [[ ! -f "$config_path" ]]; then
   				touch /etc/wireguard/"$wg_port_name".conf
   				return 0
			else
				echo -e "${RED}File name already in use, please remove file from /etc/wireguard or choose another name for the Wireguard Port.${NC}"
			fi
		elif [[ -z "$wg_port_name" ]]; then
			return 1
   		else
	 		echo -e "${RED}Not a valid input. Must be an alphanumeric input.${NC}"
		fi
  	done
}

# checks to see if the config file is set up to be a peer. If it is, it will tell the user.
config_file_check_peer() {
	if grep -qi '^Endpoint' $config_choice_final; then
		echo -e "\n ${RED}**ERROR**${NC} This config file is set up to be a Peer. Please choose the correct config:"
		return 1
	fi
}

# Checks to see if the config file is set up to be a server. If it is, it will tell the user.
config_file_check_server() {
	if grep -qi '^ListenPort' $config_choice_final; then
		echo -e "\n ${RED}**WARNING**${NC} This config file is set up to be a Server. Please try again."
		return 1
	fi
}

# Checks to make sure there isn't another input of the same in the config file.
unique() {
	local var_name="$1"
	if grep -qwi "$var_name" "$config_choice_final"; then
		echo -e "\n${RED}ERROR${NC}"
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
	
	sed -i "/^alias ${wg_port_name}_private_key=/d" ~/.bashrc
	printf 'alias %s="cat /etc/wireguard/%s_private.key"\n' "${wg_port_name}_private_key" "$wg_port_name" >> ~/.bashrc
	sed -i "/^alias ${wg_port_name}_public_key=/d" ~/.bashrc
	printf 'alias %s="cat /etc/wireguard/%s_public.key"\n' "${wg_port_name}_public_key" "$wg_port_name" >> ~/.bashrc
}

# print the public key for the user to use in clients.
print_public_key_set_aliases() {
	echo -e "\nPrinting the Public key:\n\n${GREEN}$public_key${NC}\n\n"
	echo "Please copy this key to use for setting up the client."
 	echo -e "${YELLOW}Aliases are set.\nManually run 'source ~/.bashrc' or open a new terminal to use them.${NC}" 

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
	if ! grep -q "Peer" "$config_choice_final"; then
		echo -e "No ${CYAN}peers${NC} found. Start by adding a ${CYAN}peer${NC} with option 1."
	else
		awk -F' = ' -v cyan="$CYAN" -v nc="$NC" '
			/^# /{
				# Extract name after "# "
				name = $0
				sub(/^# /, "", name)
			}
			/^AllowedIPs/{
				# Extract IP and remove CIDR notation
				ip = $2
				sub(/\/[0-9]+$/, "", ip)
				# Print immediately for piping to sort
				printf "%s|%s\n", ip, name
			}
		' "$config_choice_final" | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n | \
		awk -F'|' -v cyan="$CYAN" -v nc="$NC" '{
			printf "%s%s%s %s\n", cyan, $2, nc, $1
		}'
	fi
}

peer_check() {
	if ! grep -q "Peer" "$config_choice_final"; then
		echo -e "\n${RED}ERROR:${NC} No ${CYAN}peers${NC} found. Please add a ${CYAN}peer${NC}."
		return 1
	fi
}

# Enables the Wireguard port as a service to start on boot.
enable_wg() {
	echo "Enabling the port to start on boot..."
	systemctl enable wg-quick@"$wg_port_name".service &> /dev/null \
	&& systemctl daemon-reload &> /dev/null \
	&& systemctl start wg-quick@"$wg_port_name" &> /dev/null
	echo -e "${GREEN}The Wireguard installation has been completed!${NC}"
}

# Exit to the previous menu
exit_selection() {
	echo "Exiting..."
}

invalid_option() {
	echo -e "${RED}Invalid option. Please try again.${NC}"
}

ping_test() {
	local peer_ping="$1"
	if ping -q -c 1 -w 1 "$peer_ping" &> /dev/null; then
		echo -e "${GREEN}Ping to the EndPoint, ${peer_ping} was successful!${NC}"
	else
		echo -e "${YELLOW}WARNING:${NC} Ping was not successful."
	fi
}

##################
# MENU FUNCTIONS #
##################

# Main menu of the wireguard script.
main_menu() {
	echo
	cat << EOF
${CYAN}	###################
	#### MAIN MENU ####
	###################
${NC}
Choose your ${GREEN}Wireguard${NC} install type:

1. (OPTIONAL) Set ${CYAN}Static IP${NC}. (Recommended for Option #2)
2. ${CYAN}Server${NC} Install and Setup.
3. ${CYAN}Server${NC} Config edit.
4. ${CYAN}Client${NC} Install and Setup.
5. ${CYAN}Client${NC} Config edit.
6. ${YELLOW}Info and commands${NC}.
7. ${RED}Delete and cleanup${NC}.

Type "exit" (or ctrl + c) to exit the script.
EOF

	read -rp ": " install_type
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
	echo -e "${RED}\n***WARNING***\nOnce you change the IP, you MAY be disconnected.\nIf that happens, you will need to re-connect using the correct IP.${NC}\n"
	check_input_validate $'Input the static IP you would like the Wireguard Server to use. (e.g. 192.168.1.2)\n: ' static_ip valid_ip_check "$ip_type"
	check_user_input_Y_n  "Are you sure you want to use ${static_ip}? (Y/n)" || return 1
	sed -i "/address/c\        address "$static_ip" " $net_interf \
	&& echo -e "\n${GREEN}Address has been updated.${NC}\n"
}

# Adds the CIDR notation to the end of the user inputed static IP.
main_1_cidr_edit() {
	echo "Enter the subnet in CIDR notation. Numbers Only."
	default_cidr_validate $': ' cidr_input cidr_check "$cidr_type"
	check_user_input_Y_n "Are you sure you want to use $cidr_input? (Y/n)" || return 1
	sed -i "/"$static_ip"/c\        address "$static_ip"\/"$cidr_input" " $net_interf \
	&& echo -e "\n${GREEN}Subnet has been updated.${NC}\n"
}

# Edits the gateway for static IP
main_1_gateway_edit() {
	check_input_validate $'Input the gateway\n: ' static_gw valid_ip_check "$ip_type"
	check_user_input_Y_n "Are you sure you want to use $static_gw? (Y/n)" || return 1
	sed -i "/gateway/c\        gateway "$static_gw" " $net_interf \
	&& echo -e "\n${GREEN}Gateway has been changed.${NC}\n"
}

main_1_apply_network() {
	echo -e "${GREEN}Network settings have been updated, and network has been refreshed.\nPlease connect using the new IP.\n${RED}Exiting script.${NC}"
	systemctl restart networking
	exit 1
}

main_2_file_check_server() {
    shopt -s nullglob
	config_files_array=(/etc/wireguard/*.conf)
    if ((${#config_files_array[@]} > 0)); then
        for config_file in "${config_files_array[@]}"; do
            if grep -q '^PreUp = sysctl -w net.ipv4.ip_forward=1' "$config_file"; then
                echo -e "\n${RED}There is already a server configuration file configured. Run Option 3, Server Peer Config.${NC}"
				return 1
            fi
        done
    else
        echo -e "${GREEN}There are no server configuration files found. Continuing...${NC}"
    fi

	shopt -u nullglob
}

# Installs programs needed for Server.
main_2_program_check() {
	spin &
  	spinpid=$!
	check_install "wireguard"
  	check_install "iptables"
	check_install "openssh-client"
	check_install "openssh-server"
	check_install "openssh-sftp-server"
 	check_install "openresolv"
  	kill "$spinpid" 2>/dev/null
  	wait "$spinpid" 2>/dev/null
  	printf '\r \r'  # Clear the spinner line completely
}

# user input for server IP and Network
main_2_server_network() {
	echo -e "\nEnter the ${CYAN}IP address${NC} the server will use. This will act as a gateway."
 	echo -e "${YELLOW}NOTE:${NC} Make it a non-conflicting IP from your other networks that you are connecting."
  	echo "${YELLOW}Example:${NC} 10.15.0.1, 172.16.0.1, or 192.168.6.1."
 	check_input_validate ": " server_network_input valid_ip_check "$ip_type"
}

# Checks and makes the config folder
main_2_server_config() {
	if [ -f "$config_path" ]; then
		cat <<EOF > "$config_path"
[Interface]
PrivateKey = $private_key
Address = $server_network_input/32
ListenPort = $port_num
# IP forwarding
PreUp = sysctl -w net.ipv4.ip_forward=1
# This makes the server act as a router on the network.
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o $interf -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o $interf -j MASQUERADE
EOF
	fi
}

# Client Peer selection menu.
main_3_selection_submenu() {
	echo
	cat << EOF

Server Peer Configuration

1. Add a new client.
2. Edit a client.
3. Remove a client.
4. Return to the previous menu.
EOF

	read -rp ": " peer_choice
}

sub_3.1_peer_input() {
	while true; do
		echo -e "\nEnter a name for the ${CYAN}peer${NC}. Leave blank to return to previous menu."
		check_input_validate_space $': ' peer_name alphanumeric_check "$alphanumeric_type" || return 1
		unique "$peer_name" || continue
		break
	done
}

sub_3.1_peer_IP() {
	while true; do
		echo -e "\nEnter the ${CYAN}private IP address${NC} for the peer to use. Leave blank to return to previous menu."
		check_input_validate_space $': ' peer_ip valid_ip_check "$ip_type" || return 1
		unique "$peer_ip" || continue
		break
	done
}

sub_3.1_public_key() {
	while true; do
		echo -e "\nEnter the ${CYAN}PublicKey${NC} from the client. Leave blank to return to previous menu."
		check_input_validate_space $': ' peer_key key_check "$key_type" || return 1
		unique "$peer_key" || continue
		break
	done
}

# Adds a peer to the server config.
sub_3.1_peer_config() {
	cat <<EOF >> "$config_choice_final"
[Peer]
# $peer_name
PublicKey = $peer_key
AllowedIPs = $peer_ip/32
EOF
	echo -e "\n${GREEN}Peer added successfully. Restarting Wireguard...${NC}" \
	&& systemctl restart wg-quick@$config_basename.service
}

sub_3.2_user_select() {
	while true; do
		echo -e "\nWhich user would you like to edit?\n${YELLOW}NOTE:${NC} Name only. Case sensitive. Leave blank to return to previous menu."
		read -rp $': ' user_select_3_2
		if grep -qx "# $user_select_3_2" "$config_choice_final"; then
			return 0
		elif [[ -z "$user_select_3_2" ]]; then
			return 1
		else
			echo -e "${RED}User not found. Please try again.${NC}"
		fi
	done
}

sub_3.2_menu() {
	echo -e "\nYou chose: ${CYAN}${user_select_3_2}${NC}. Here is their connection information:"
	grep -x -A 2 "# $user_select_3_2" "$config_choice_final" | awk "NR > 1" | sed "s/^PublicKey/${CYAN}&${NC}/" | sed "s/^AllowedIPs/${CYAN}&${NC}/"
	echo
	cat << EOF
Which setting would you like to edit?

1. Change the ${CYAN}PublicKey${NC}.
2. Change the user's ${CYAN}private IP address${NC} under ${CYAN}AllowedIPs${NC}.
3. Return to the previous menu.
EOF

	read -rp ": " setting_select_3_2
}

sub_3.2.1_change_public_key() {
	while true; do
		echo -e "\nEnter the new ${CYAN}PublicKey${NC} you would like to use. Leave blank to return to previous menu."
		check_input_validate_space $': ' new_public_key key_check "$ip_type" || return 1
		unique "$new_public_key" || continue
		sed -i "/# $user_select_3_2/,/^\[Peer\]/ { s|^PublicKey =.*|PublicKey = ${new_public_key}| }" "$config_choice_final" \
		&& echo -e "${GREEN}Public Key has been changed. Restarting Wireguard...${NC}" \
		&& systemctl restart wg-quick@${config_basename}.service
		break
	done
}

sub_3.2.2_change_ip() {
	while true; do
		echo -e "\nEnter the new ${CYAN}private IP address${NC} you would like to use. Leave blank to return to previous menu."
		check_input_validate_space $': ' new_ip valid_ip_check "$ip_type" || return 1
		unique "$new_ip" || continue
		sed -i "/# $user_select_3_2/,/^\[Peer\]/ { s/^AllowedIPs =.*/AllowedIPs = ${new_ip}\/32/ }" "$config_choice_final" \
		&& echo -e "${GREEN}The IP has been changed. Restarting Wireguard...${NC}" \
		&& systemctl restart wg-quick@${config_basename}.service
		break
	done
}

# Deletes a peer from the server config.
sub_3.3_delete() {
	while true; do
		echo -e "\nWhich user would you like to delete?"
		echo -e "${YELLOW}NOTE:${NC} Name only. Case sensitive. Leave blank to return to previous menu."
		read -rp $': ' user_select
		if [[ -z "$user_select" ]]; then
			echo "Returning to previous menu."
			return 1
		elif grep -q "# $user_select" "$config_choice_final"; then
			if check_user_input_y_N "Are you sure you want to delete user '${user_select}'? (Y/n): "; then
				sed -i "/\[Peer\]/ { N; /\n# $user_select/ { N; N; d; } }" "$config_choice_final"
				sed -i '/^$/N;/^\n$/D' "$config_choice_final"
				echo -e "${RED}User '$user_select' deleted.${NC}" \
				&& systemctl restart wg-quick@${config_basename}.service
				return 0
			else
				return 1
			fi
		else
			echo -e "${RED}User not found, please try again.${NC}"
		fi
	done
}

main_4_private_IP() {
	echo -e "\nEnter the ${CYAN}Private IP Address${NC} this client will use."
	check_input_validate $': ' peer_address valid_ip_check "$ip_type"
	peer_address_change="${peer_address%.*}.0"
}

main_4_public_key() {
	echo -e "\nEnter the ${CYAN}PublicKey${NC} of the remote Wireguard server or client this client will connect to."
	check_input_validate $': ' peer_pk key_check "$key_type"
}

main_4_collect_networks_loop() {
	local ip_list=()
	while true; do
		echo -e "\nEnter the ${CYAN}Allowed Network(s)${NC} for the ${CYAN}AllowedIPs${NC} section."
		echo -e "${YELLOW}EXAMPLE:${NC} \"${peer_address_change}\"."
		echo -e "${YELLOW}NOTE:${NC} 0.0.0.0 entered means a full tunnel connection."
		check_input_validate $': ' allowed_ips_peer valid_ip_check "$ip_type"
		if [ "$allowed_ips_peer" = 0.0.0.0 ]; then
			collected_ips="0.0.0.0/0"
			echo -e "\nAdded ${CYAN}0.0.0.0/0${NC} to ${CYAN}AllowedIPs${NC}."
			echo -e "\n${RED}WARNING!!!${NC} This will disconnect your connection if you are remoting into this machine."
			break
		else
			echo -e "\nPlease enter the CIDR of your ${CYAN}Allowed Network${NC}."
			default_cidr_validate $': ' allowed_ip_cidr cidr_check "$cidr_type"
			ip_list+=("$allowed_ips_peer"/"$allowed_ip_cidr")
			collected_ips=$(IFS=, ; echo "${ip_list[*]}")
			echo -e "\nWould you like to add another ${CYAN}Allowed Network${NC}? (y/N)"
			check_user_input_y_N $': ' || break
		fi
	done
}

main_4_endpoint() {
	echo -e "\nPlease enter the ${CYAN}Endpoint${NC} IP of the remote Wireguard server or client. (LAN for inside network, WAN for outside)."
	echo -e "${YELLOW}NOTE:${NC} DDNS is supported."
	check_input_validate_2 $': ' endpoint_address valid_ip_check valid_ddns_check "$multi_type"
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
PersistentKeepalive = 25
EOF
	fi
}

main_5_menu() {
	echo
	cat << EOF
Which setting would you like to edit?

1. Edit the client's ${CYAN}private IP address${NC}.
2. Edit the remote's ${CYAN}PublicKey${NC}.
3. Edit Allowed Networks. (${CYAN}AllowedIPs${NC})
4. Edit the IP and Port of the ${CYAN}Endpoint${NC}. (The server this peer is connecting to.)
5. Return to the previous menu.
EOF

	read -rp ": " setting_select_5
}

sub_5.1_edit_ip() {
	echo -e "\nHere is the ${CYAN}private IP address${NC} for this connection:"
	grep '^Address' "$config_choice_final" | sed "s/^Address/${CYAN}&${NC}/"
	echo -e "Enter the new ${CYAN}private IP address${NC} you would like to use."
	check_input_validate $': ' new_peer_ip valid_ip_check "$ip_type" \
	&& sed -i "/^Address =/c\Address = $new_peer_ip" "$config_choice_final" \
	&& echo -e "${GREEN}The IP has been changed. Restarting Wireguard...${NC}" \
	&& systemctl restart wg-quick@${config_basename}.service
}

sub_5.2_edit_public_key() {
	echo -e "\nHere is the ${CYAN}PublicKey${NC} for the remote Wireguard server:\n"
	grep '^PublicKey' "$config_choice_final" | sed "s/^PublicKey/${CYAN}&${NC}/"
	echo -e "Please enter the new ${CYAN}PublicKey${NC}."
	check_input_validate $': ' new_peer_public_key key_check "$key_type" \
	&& sed -i "/^PublicKey =/c\PublicKey = $new_peer_public_key" "$config_choice_final" \
	&& echo -e "${GREEN}The Public Key has been changed. Restarting Wireguard...${NC}" \
	&& systemctl restart wg-quick@${config_basename}.service
}

sub_5.3_echo() {
	echo -e "\nHere are the ${CYAN}AllowedIPs${NC}:"
	grep "^AllowedIPs" "$config_choice_final" | sed "s/^AllowedIPs/${CYAN}&${NC}/"
	echo -e "\n${YELLOW}NOTE:${NC}\nUse a 0 in the 4th octet.\n0.0.0.0/0 entered means a full tunnel connection."
}

sub_5.3_sub_menu() {
	echo
	cat << EOF
1. Change ${CYAN}AllowedIPs${NC}. (This will change the line back to one network allowed.)
2. Append a new network to end of the ${CYAN}AllowedIPs${NC} list.
3. Return to the previous menu.
EOF

	read -rp $': ' allowed_input
}

sub_5.3.1_change_ip() {
	echo -e "Enter the new ${CYAN}AllowedIPs${NC}."
	check_input_validate $': ' allowed_ip_input valid_ip_check "$ip_type" \
	&& sed -i "/^AllowedIPs =/c\AllowedIPs = $allowed_ip_input" "$config_choice_final"
	echo "Enter the CIDR. Numbers only."
	default_cidr_validate $': ' allowed_cidr_input cidr_check "$cidr_type" \
	&& sed -i "/^AllowedIPs/s|$|/$allowed_cidr_input|" "$config_choice_final" \
	&& systemctl restart wg-quick@$config_basename.service \
	&& echo -e "${GREEN}Allowed Network has been updated and the Wireguard service has been restarted.${NC}"
}

sub_5.3.2_append_ip() {
	echo -e "Enter the new, additional ${CYAN}AllowedIPs${NC}."
	check_input_validate $': ' allowed_ip_input2 valid_ip_check "$ip_type" \
	&& sed -i "/^AllowedIPs/s|$|, $allowed_ip_input2|" "$config_choice_final"
	echo "Enter the CIDR. Numbers only."
	default_cidr_validate $': ' allowed_cidr_input2 cidr_check "$cidr_type" \
	&& sed -i "/^AllowedIPs/s|$|/$allowed_cidr_input2|" "$config_choice_final" \
	&& systemctl restart wg-quick@$config_basename.service \
	&& echo -e "${GREEN}Allowed Network has been updated and the Wireguard service has been restarted.${NC}"
}

sub_5.4_endpoint_edit_menu() {
	echo -e "\nHere is the IP and port of the remote Wireguard server this peer connects to:"
	grep "^Endpoint" "$config_choice_final" | sed "s/^Endpoint/${CYAN}&${NC}/"
	echo
	cat << EOF
1. Edit the remote's ${CYAN}Endpoint${NC} IP. (This is the IP used to communicate to the remote Wireguard Server.)
2. Edit the remote's ${CYAN}Endpoint${NC} port.
3. Return to the previous menu.
EOF

	read -rp $': ' wan_peer_input
}

sub_5.4.1_change_endpoint() {
	echo "Enter the remote server IP that this peer will connect to."
	echo -e "${YELLOW}NOTE:${NC} DDNS is supported."
	check_input_validate_2 $': ' wan_peer_change valid_ip_check valid_ddns_check "$multi_type" \
	&& sed -i -E "s/(Endpoint = )([^:]+)(:[0-9]+)/\1$wan_peer_change\3/" "$config_choice_final" \
	&& echo -e "${GREEN}The IP has been changed. Restarting Wireguard...${NC}" \
	&& systemctl restart wg-quick@$config_basename.service
}

sub_5.4.2_change_port() {
	default_port \
	&& sed -i -E "s/(Endpoint = [^:]+:)[0-9]+/\1$port_num/" "$config_choice_final" \
	&& echo "The port has been changed. Restarting Wireguard..." \
	&& systemctl restart wg-quick@$config_basename.service
}

main_6_help_menu() {
	echo
	cat << EOF
Info and commands. Choose an option:
1. Print useful connection info. (For connecting to other clients).
2. wg (Command to see peers and public key.)
3. Print the configuration file.
4. Useful Commands.
5. Return to the previous menu.
EOF
	read -rp ": " help_input
}

sub_6.1_info () {
	if grep -q '^PreUp = sysctl -w net.ipv4.ip_forward=1' "$config_choice_final"; then
		echo -e "\n${CYAN}Configuration Type:${NC} \nServer"
		echo -e "\n${CYAN}Server's IP Address:${NC}"
		grep '^Address' "$config_choice_final" | awk '{print $3}' | tr -d '/32'
		echo -e "\n${CYAN}Listening Port:${NC}"
		grep '^ListenPort' "$config_choice_final" | awk '{print $3}'
	elif grep -q '^Endpoint' "$config_choice_final"; then
		echo -e "\n${CYAN}Configuration Type:${NC} \nClient"
		echo -e "\n${CYAN}Private IP Address:${NC}"
		grep '^Address' "$config_choice_final" | awk '{print $3}'
	else
		echo "ERROR"
	fi
	echo -e "\n${CYAN}Public Key:${NC}"
	grep "PrivateKey =" "$config_choice_final" | awk '{print $3}' | wg pubkey
	echo -e "\n${CYAN}Local IP:${NC}"
	hostname -I | awk '{print $1}'
	echo -e "\n${CYAN}WAN IP:${NC}"
	wget -qO- https://ipinfo.io | grep "ip" | awk 'NR == 1 {print $2}' | tr -d '",'
}

sub_6.1_wg_command() {
	if wg show &> /dev/null; then
    	wg show
	else
    	echo -e "\n${RED}ERROR:${NC} wg command failed. No WireGuard interface may be configured or running."
	fi
}

sub_6.4_commands() {
	commands_text=$(cat <<EOF

${YELLOW}wg${NC} (Command for Wireguard to print connections and public key of server)
${YELLOW}systemctl start wg-quick@${GREEN}INTERFACE${NC} (Starts the Wireguard interface service)
${YELLOW}systemctl stop wg-quick@${GREEN}INTERFACE${NC} (Stops the Wireguard interface service)
${YELLOW}systemctl restart wg-quick@${GREEN}INTERFACE${NC} (Restarts the Wireguard interface service)
${YELLOW}systemctl status wg-quick@${GREEN}INTERFACE${NC} (Shows the status of the Wireguard interface service)
${YELLOW}nano /etc/wireguard/${GREEN}INTERFACE.conf${NC} (Edits the config file)
${YELLOW}cat /etc/wireguard/${GREEN}INTERFACE${YELLOW}_public_key or ${GREEN}INTERFACE${YELLOW}_public_key${NC} (Prints the Public Key of the server)
${YELLOW}cat /etc/wireguard/${GREEN}INTERFACE${YELLOW}_private_key or ${GREEN}INTERFACE${YELLOW}_private_key${NC} (Prints the Private Key of the server)

After configuring a wireguard port, run '${YELLOW}source ~/.bashrc${NC}' to load in aliases:
${GREEN}INTERFACE${YELLOW}start${NC} will execute the same as ${YELLOW}systemctl start wg-quick@${GREEN}INTERFACE${NC}
${GREEN}INTERFACE${YELLOW}stop${NC} will execute the same as ${YELLOW}systemctl stop wg-quick@${GREEN}INTERFACE${NC}
${GREEN}INTERFACE${YELLOW}restart${NC} will execute the same as ${YELLOW}systemctl restart wg-quick@${GREEN}INTERFACE${NC}
${GREEN}INTERFACE${YELLOW}status${NC} will execute the same as ${YELLOW}systemctl status wg-quick@${GREEN}INTERFACE${NC}
EOF
)

	echo -e "$commands_text"
}

main_7_delete_menu() {
	echo
	cat << EOF
Choose which option you'd like to do:

1. Delete an interfaces' config file and remove its aliases.
2. Remove Wireguard, delete all config files and aliases.
3. Return to the previous menu.

EOF

	read -rp ": " cleanup_input
}

sub_7.1_rm_single_config() {
	echo -e "${RED}***WARNING***${NC} Are you sure you want to delete this config file? (y/N)\n"
	if check_user_input_y_N $': '; then
		rm -f "${config_choice_final%.*}"*
		unset "$config_basename"_public_key
		unset "$config_basename"_private_key
		sed -i "/^alias ${config_basename}/d" ~/.bashrc
		sed -i "/${config_basename}_private_key=/d" ~/.bashrc
		sed -i "/${config_basename}_public_key=/d" ~/.bashrc
		modprobe -r wireguard
		echo -e "${GREEN}Success${NC} Returning to previous menu"
	else
		return 1
	fi
}

sub_7.2_rm_wireguard() {
	unset config_basename
	echo -e "${RED}***WARNING***${NC} Are you sure you want to delete wireguard and all of it's configurations? (y/N)\n"
	if check_user_input_y_N $': '; then
		config_basenames=()
		for file in /etc/wireguard/*.conf; do
			if [ -f "$file" ]; then
				config_basenames+=("$(basename "$file" .conf)")
			fi
		done

		rm -r /etc/wireguard/

		for config_basename in "${config_basenames[@]}"; do
			sed -i "/^alias ${config_basename}_/d" ~/.bashrc
			sed -i "/^alias ${config_basename}start=/d" ~/.bashrc
			sed -i "/^alias ${config_basename}stop=/d" ~/.bashrc
			sed -i "/^alias ${config_basename}status=/d" ~/.bashrc
			sed -i "/^alias ${config_basename}restart=/d" ~/.bashrc
		done
		
		apt-get remove --purge wireguard wireguard-tools -y \
		&& apt autoremove -y \
		&& modprobe -r wireguard
		echo -e "\n${GREEN}Success!${NC} Returning to previous menu."
	fi
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
			DNS_check
   			run_apt_update
			main_2_program_check
			config_file_creation || continue
   			wg_keygen
			main_2_server_network
			default_port
	  		main_2_server_config
			enable_wg
   			print_public_key_set_aliases
		;;
  		3)  # Server Peer editing.
			while true; do
	   			config_file_check || break
				choosing_config || continue
	   			config_file_check_peer || break
	   			server_peer_show
	   			main_3_selection_submenu
	   			case "$peer_choice" in
	   				1) # Add a Peer.
	  					sub_3.1_peer_input || continue
	  					sub_3.1_peer_IP || continue
						sub_3.1_public_key || continue
						sub_3.1_peer_config && break
					;;
	 				2) # Edit a Peer.
						peer_check || continue
						while true; do
							sub_3.2_user_select || break
							sub_3.2_menu
							case "$setting_select_3_2" in
								1)
									sub_3.2.1_change_public_key && break || continue
								;;
								2)
									sub_3.2.2_change_ip && break || continue
								;;
								3)
									exit_selection && break
								;;
								*)
									invalid_option
								;;
							esac
						done
	  				;;
					3) # Delete a Peer.
						peer_check || continue
						sub_3.3_delete || continue
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
  		4) # installs a wireguard peer.
			DNS_check
			run_apt_update
			check_install "wireguard"
			check_install "openresolv"
			config_file_creation || continue
			wg_keygen
			main_4_private_IP
			main_4_public_key
			main_4_collect_networks_loop
			main_4_endpoint
			default_port
			main_4_peer_config
			print_public_key_set_aliases
			enable_wg
		;;
		5) # Client Peer Config.
			while true; do
				config_file_check || break
				choosing_config || continue
				config_file_check_server || break
				main_5_menu
				case "$setting_select_5" in
					1) # Edits the IP Address of the Peer Config.
						sub_5.1_edit_ip
					;;
					2) # Edits the PublicKey of the Remote Wireguard Server this peer is connecting to.
						sub_5.2_edit_public_key
					;;
					3) # Edit the Allowed IP's section. I've named it "Allowed Networks".
						while true; do
							sub_5.3_echo
							sub_5.3_sub_menu
							case "$allowed_input" in
								1) # Change the IP.
									sub_5.3.1_change_ip
								;;
								2) # Append a new Allowed Network.
									sub_5.3.2_append_ip
								;;
								3) # Exits the menu
									exit_selection && break
								;;
								*) # all other options are invalid.
									invalid_option
								;;
							esac
						done
					;;
					4) # Edit the Endpoint of the remote Wireguard server this Peer is connecting to
						while true; do
	 						sub_5.4_endpoint_edit_menu
							case "$wan_peer_input" in
								1) # change the Endpoint for connection.
									sub_5.4.1_change_endpoint
								;;
								2) # Change the port
									sub_5.4.2_change_port
								;;
								3) # Exits the menu
									exit_selection && break
								;;
								4) # All other options are invalid.
									invalid_option
								;;
							esac
						done
					;;
					5) # Exits the menu
						exit_selection && break
					;;
					*) # All other options are invalid.
						invalid_option
					;;
				esac
			done
  		;;
		6) # Info and commands.
			while true; do
				main_6_help_menu
				case "$help_input" in
					1) # Prints useful commands
						config_file_check || continue
						choosing_config && sub_6.1_info
					;;
					2) # Wireguard command to print connections and public key(s).
						sub_6.1_wg_command
					;;
					3) # Prints the config file
						config_file_check || continue
						choosing_config && cat "$config_choice_final"
					;;
					4) # Prints useful commands
						sub_6.4_commands
					;;
					5) # Exits the menu
						exit_selection && break
					;;
					6) # Pings an endpoint
					
					;;
					*)
						invalid_option
					;;
				esac
			done
  		;;
		7) # Delete and cleanup
			while true; do
				main_7_delete_menu
				case "$cleanup_input" in
					1) # Deletes a single configuration file and its aliases.
						choosing_config || break
						sub_7.1_rm_single_config || break
						break
					;;
					2) # Deletes Wireguard, all configuration files and removes all aliases.
						sub_7.2_rm_wireguard
						break
					;;
					3) # Exits the menu
						exit_selection && break
					;;
					*) # All other options are invalid.
						invalid_option
					;;
				esac
			done
  		;;
		exit)
  			exit_selection && break
		;;
  		*)
			invalid_option
   		;;
	esac
done
