###################################################################################################
#
# File        : fimon_main.sh
# Version     : 2023.11.03
# Usage       : sh ./fimon_main.sh
# Description : File Integrity Monitoring on Unix servers
#               This file is to be called by Cron Scheduler to run the provided shell script and json file.
# Contact     :
# Keywords    : Monitor , Monitoring , Integrity, Audit
#
# IMPORTANT   : Users are NOT required to update or make changes to this script.
#               Users are ONLY required to make updates to the config file - fimon_config.json
#
###################################################################################################

# !/bin/sh
# set -x

datetime=$(date +'%Y%m%d'_%H%M)
cdir=$(dirname "$0")
log_file="$cdir/fimon.log"

>$log_file
sh ./fimon.sh $datetime >>$log_file
sh ./fimon.sh $datetime $log_file
