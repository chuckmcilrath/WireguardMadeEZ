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
net_int=/etc/network/interfaces
wg_port_num=/etc/wireguard/
