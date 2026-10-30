#!/bin/sh
set -eu

source_file=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/custom-alertmind
destination=${1:-/var/ossec/integrations/custom-alertmind}

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this installer as root (for example: sudo $0)." >&2
    exit 1
fi

if [ ! -d "$(dirname -- "$destination")" ]; then
    echo "Wazuh integration directory not found: $(dirname -- "$destination")" >&2
    exit 1
fi

install -o root -g wazuh -m 750 "$source_file" "$destination"
echo "Installed $destination"
echo "Next: add integrations/ossec.conf.example.xml to the existing ossec_config,"
echo "then validate the config and restart wazuh-manager during an approved window."
