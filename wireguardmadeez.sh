#!/bin/bash

##########################################################################################################################################################
#                                                                                                                                                        #
# wget -O wireguard.sh https://raw.githubusercontent.com/chuckmcilrath/WireguardMadeEZ/refs/heads/main/wireguardmadeez.sh && ./wireguard.sh
#                                                                                                                                                        #
##########################################################################################################################################################

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

# Check user input is 256-bit key
key_check() {
    local key="$1"
	
    [[ "$key" =~ ^[A-Za-z0-9+/]{43}=$ ]] && return 0
    return 1
}
