#!/bin/bash

##########################################################################################################################################################
#                                                                                                                                                        #
# wget -O wireguard.sh https://raw.githubusercontent.com/chuckmcilrath/scripts/refs/heads/main/Wireguard_Script && chmod +x wireguard.sh && ./wireguard.sh
#                                                                                                                                                        #
##########################################################################################################################################################

####################
# GLOBAL VARIABLES #
####################

resolved_path=/etc/systemd/resolved.conf
net_int=/etc/network/interfaces
wg_port_num=/etc/wireguard/
