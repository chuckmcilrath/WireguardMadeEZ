#!/bin/bash

#########################################################################################################################################################
#                                                                                                                                                       #
# wget -O wireguardmadeez.sh https://raw.githubusercontent.com/chuckmcilrath/WireguardMadeEZ/refs/heads/main/wireguardmadeez.sh && ./wireguardmadeez.sh #
#                                                                                                                                                       #
#########################################################################################################################################################

####################
# GLOBAL VARIABLES #
####################

resolved_path=/etc/systemd/resolved.conf
net_interf=/etc/network/interfaces
wg_port_num=/etc/wireguard/"$wg_interf"

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

# Edits the IP (Only the IP)
main_1_static_ip_edit() {
	while true; do
		read -p $'Input the static IP you would like the Wireguard Server to use. (e.g. 192.168.1.2)\n: ' static_ip
		if is_valid_ip "$static_ip"; then
			while true; do
				echo "Are you sure you want to use $static_ip? (y/n)"
				read -p ": " static_confirm
				if [[ $static_confirm == y ]]; then
					if grep -q address $net_int; then
						sed -i "/address/c\        address "$static_ip" " $net_int \
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
				if grep -q "$static_ip" $net_int; then
					sed -i "/"$static_ip"/c\        address "$static_ip"\/"$cidr_input" " $net_int \
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
					if grep -q address $net_int; then
						sed -i "/gateway/c\        gateway "$static_gw" " $net_int \
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

# STARTING OPTIONS
main_menu() {
	echo
	cat << EOF
Choose the install type:

1. (OPTIONAL) Set Static IP
2. Wireguard Server Install and Setup
3. Wireguard Server Peer Config
4. Client Peer Install and Setup
5. Client Peer Config
6. Troubleshooting and help
7. Delete and cleanup

Type "exit" to exit the script
EOF

read -p ": " install_type
}

###################
# Start of script #
###################
while true; do
	main_menu
 	case "$install_type" in
  		1)
			main_1_static_ip_edit
			main_1_cidr_edit
   			main_1_gateway_edit
		;;
  		2)
		;;
  		3)
		;;
  		4)
		;;

  		*)
			echo "Invalid Option. Please try again."
   		;;
	esac
done
