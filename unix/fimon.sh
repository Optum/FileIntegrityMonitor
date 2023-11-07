###################################################################################################
#
# File        : fimon.sh
# Version     : 2023.11.03
# Usage       : sh ./fimon_main.sh
# Description : File Integrity Monitoring on Unix servers
#               Script includes embedded webhooks to an Event Mgmt tool for state based events triggers including reset event
#
# IMPORTANT   : Users are NOT required to update or make changes to this script.
#               Users are ONLY required to make updates to the config file - fimon_config.json
#
###################################################################################################

# !/bin/sh
# set -x

start=$(date +%s)
datetime=$1
log_file=$2

cdir=$(dirname "$0")
config_file="$cdir/fimon_config.json"

touch "$cdir/cron.err"
touch "$cdir/cron.out"
chmod 755 "$cdir/cron.err"
chmod 755 "$cdir/cron.out"

###################################################################################################
#
# Parsing JSON data
#
###################################################################################################

config_application=$(cat $config_file | jq -r ".application")
config_severity=$(cat $config_file | jq -r ".severity")
config_domain=$(hostname --fqdn)
config_autoincident=$(cat $config_file | jq -r ".autoincident")
config_workgroup=$(cat $config_file | jq -r ".workgroup")
config_core_api_token_key=$(cat $config_file | jq -r ".core_api_token_key")
config_core_api_token_value=$(cat $config_file | jq -r ".core_api_token_value")
config_core_endpoint=$(cat $config_file | jq -r ".core_endpoint")
config_is_dmz=$(cat $config_file | jq -r ".is_dmz")
config_dmz_endpoint=$(cat $config_file | jq -r ".dmz_endpoint")
config_is_external=$(cat $config_file | jq -r ".is_external")
config_ext_endpoint=$(cat $config_file | jq -r ".ext_endpoint")
config_ext_api_token_key=$(cat $config_file | jq -r ".ext_api_token_key")
config_ext_api_token_value=$(cat $config_file | jq -r ".ext_api_token_value")
config_ext_oauth_token=$(cat $config_file | jq -r ".ext_oauth_token")
config_event_query=$(cat $config_file | jq -r ".event_query")
config_event_oauth_token=$(cat $config_file | jq -r ".event_oauth_token")
config_telemetry_token=$(cat $config_file | jq -r ".telemetry_token")
config_telemetry_endpoint=$(cat $config_file | jq -r ".telemetry_endpoint")
config_continuous_change=$(cat $config_file | jq -r ".continuous_change")
config_results=$(cat $config_file | jq -r ".results")
config_targets=($(cat $config_file | jq -r ".targets[]"))
config_exclude=($(cat $config_file | jq -r ".exclude[]"))

baseline_file="$cdir/fimon_baseline.json"
audit_results="$config_results/fimon_$datetime"
exclusions="$audit_results/fimon_exclusions_$datetime.csv"
violations="$audit_results/fimon_violations_$datetime.csv"

echo "Application Name:     $config_application"
echo "Config File:          $config_file"
echo "Baseline File:        $baseline_file"
echo -e "Audit Results Folder: $audit_results\n"
for target in ${config_targets[@]}; do echo "Target: $target"; done
echo "Excluded Filetypes: ${config_exclude[@]}"

# Current inventory found during the current audit. This becomes the baseline for the next audit.
declare -A inventory

# Contains our baseline for files and checksums
declare -A baseline

# Array containing all of the audit exceptions (files added, deleted, modified) during the audit
declare -A exceptions

# Contains files facing Get-FileHash errors
declare -A failed_files
declare -A failed_files_temp

# Creating global counter variables for Grafana data
changed=0
missing=0
new=0

###################################################################################################
#
# Creating the Audit Results Folder
#
###################################################################################################

# Add $log_file to $audit_results in second run
if [ ! -z "$log_file" ]; then
    if [ -f "$log_file" ]; then
        cp $log_file $audit_results
        echo -e "\nAdded $log_file to $audit_results"
    else
        echo "ERROR3: Did not find file $log_file"
    fi
    exit
fi

# Function to group files for current run into a single folder
archive_files() {
    mkdir $audit_results
    if [ -f "$config_file" ]; then
        cp $config_file $audit_results
    else
        echo "ERROR1: Did not find file $config_file"
    fi
    if [ -f "$baseline_file" ]; then
        cp $baseline_file $audit_results
    else
        echo "ERROR2: Did not find file $baseline_file"
    fi
    if [ -f "$exclusions" ]; then
        mv $exclusions $audit_results
    fi
    if [ -f "$violations" ]; then
        mv $violations $audit_results
    fi
}

###################################################################################################
#
# Webhook to Event Management tool with Notify and Auto-Ticketing
#
###################################################################################################

webhook_call() {
    if [ "$config_is_dmz" = "true" ]; then
        endpoint=$config_dmz_endpoint
        webhook_call_external
    elif [ "$config_is_external" = "true" ]; then
        endpoint=$config_ext_endpoint
        webhook_call_external
    else
        endpoint=$config_core_endpoint
        webhook_call_core
    fi
}

webhook_call_external() {
    if [ "$config_autoincident" = "true" ]; then
        curl -k -XPOST -H "Content-type: application/json" -H $config_ext_oauth_token -d '{
            "'"$config_ext_api_token_key"'": "'"$config_ext_api_token_value"'",
            "event": {
                "application": "'"$config_application"'",
                "object": "File Integrity Monitor",
                "category": "Compliance",
                "severity": "'"$config_severity"'",
                "domain": "'"$config_domain"'",
                "title": "'"$title"'",
                "origin": "unix_fimon",
                "stateful": "true"
            },
            "incident": {
                "workgroup": "'"$config_workgroup"'"
        }}' $endpoint
    else
        curl -k -XPOST -H "Content-type: application/json" -H $config_ext_oauth_token -d '{
            "'"$config_ext_api_token_key"'": "'"$config_ext_api_token_value"'",
            "event": {
                "application": "'"$config_application"'",
                "object": "File Integrity Monitor",
                "category": "Compliance",
                "severity": "'"$config_severity"'",
                "domain": "'"$config_domain"'",
                "title": "'"$title"'",
                "origin": "unix_fimon",
                "stateful": "true"
        }}' $endpoint
    fi
}

webhook_call_core() {
    if [ "$config_autoincident" = "true" ]; then
        curl -k -XPOST -H "Content-type: application/json" -d '{
            "'"$config_core_api_token_key"'": "'"$config_core_api_token_value"'",
            "event": {
                "application": "'"$config_application"'",
                "object": "File Integrity Monitor",
                "category": "Compliance",
                "severity": "'"$config_severity"'",
                "domain": "'"$config_domain"'",
                "title": "'"$title"'",
                "origin": "unix_fimon",
                "stateful": "true"
            },
            "incident": {
                "workgroup": "'"$config_workgroup"'"
        }}' $endpoint
    else
        curl -k -XPOST -H "Content-type: application/json" -d '{
            "'"$config_core_api_token_key"'": "'"$config_core_api_token_value"'",
            "event": {
                "application": "'"$config_application"'",
                "object": "File Integrity Monitor",
                "category": "Compliance",
                "severity": "'"$config_severity"'",
                "domain": "'"$config_domain"'",
                "title": "'"$title"'",
                "origin": "unix_fimon",
                "stateful": "true"
        }}' $endpoint
    fi
}

# check_webhook_call()
# grafana_call()

###################################################################################################
#
# File Integrity Monitoring and State based event trigger
#
###################################################################################################

send_event() {
    if [ "$config_continuous_change" = "true" ]; then
        touch_file="$cdir/fimon"
        if [ ${#exceptions[@]} -eq 1 ]; then
            if [ -f "$touch_file" ]; then
                echo "File Integrity state changed to normal. Generating reset event."
                rm -f $touch_file
                config_severity="normal"
                title="Generated reset event. File Integrity Monitor detected changes. Audit Results Folder: $audit_results"
            fi
        else
            if [ -d "$audit_results" ]; then
                touch $touch_file
                title="FAILED: File Integrity Monitor detected no changes. Audit Results Folder: $audit_results"
            else
                touch $touch_file
                title="FAILED: File Integrity Monitor detected no changes. Audit Results Folder: $config_results"
            fi
        fi
    else
        if [ ${#exceptions[@]} -eq 0 ]; then
            config_severity="normal"
            title="SUCCESS: File Integrity Monitor detected no changes. Audit Results Folder: $audit_results"
        else
            if [ -d "$audit_results" ]; then
                title="FAILED: File Integrity Monitor detected changes. Audit Results Folder: $audit_results"
            else
                title="FAILED: File Integrity Monitor detected changes. Audit Results Folder: $config_results"
            fi
        fi
    fi
    echo -e "\nSeverity: $config_severity\n$title"
    webhook_call
}

process_target() {
    for target in ${config_targets[@]}; do
        echo -e "\nFetching inventory from: $target"
        start=$(date +%s)
        files=($(find $target))
        for file in ${files[@]}; do
            if [ -d "$file" ]; then
                inventory["$file"]="null"
            elif [[ ${config_exclude[@]} == *${file##*.}* ]]; then
                echo "$file" >>$exclusions
            else
                inventory["$file"]=$(md5sum $file | awk '{ print $1 }')
                # inventory["$file"]=$(stat --format="%Z" $file)
                # catch failed_files
            fi
        done
        echo "Complete. Processing time: $(($(date +%s) - $start))"
    done
}

# process_failed_files()

integrity_check() {
    # Load the existing baseline
    if [ -f "$baseline_file" ]; then
        echo -e "\nPerforming Integrity Check against Baseline file. Looking for CHANGED, MISSING, or NEW files."
        while read -r key value; do
            baseline["${key::-1}"]=$value
        done <"$baseline_file"
        rm -f $baseline_file
    else
        echo -e "\nInitial run. Creating Baseline file."
    fi

    # Save the current inventory as the new baseline
    for key in ${!inventory[@]}; do echo "$key, ${inventory[$key]}" >>$baseline_file; done

    for key in "${!baseline[@]}"; do
        if [[ ${inventory[$key]} != ${baseline[$key]} ]]; then
            exceptions+="CHANGED: $key, ${inventory[$key]}\n"
            ((changed++))
        elif [ ! ${inventory[$key]} ]; then
            exceptions+="MISSING: $key\n"
            ((missing++))
        fi
    done

    for key in "${!inventory[@]}"; do
        if [ ! ${baseline[$key]} ]; then
            exceptions+="NEW: $key, ${inventory[$key]}\n"
            ((new++))
        fi
    done

    if [ ${#exceptions[@]} -gt 0 ]; then
        echo -e "\nThere are audit exceptions. Please see Violations File for more info."
        echo -e "CHANGED: $changed\nMISSING: $missing\nNEW: $new"
        echo -e "${exceptions[@]}" >>$violations
    else
        echo -e "\nThere are no audit exceptions."
    fi
}

process_target
# process_failed_files
integrity_check
archive_files $config_file
send_event
# grafana_call
# check_webhook_call
echo -e "\n\nScript runtime: $(($(date +%s) - $start))"
