#/bin/bash

cd /mnt/hgfs/File/Code/github/passivescan/pbscan

pbscan_dir=/mnt/hgfs/File/Code/github/passivescan/pbscan
cd ${pbscan_dir}/pbscan-api/
mkdir -p /tmp/pbscan
nohup python pbscan.py -auto=8083 -headless > /tmp/pbscan/pbscan_api_8083.out &
cd ${pbscan_dir}/pbscan-server/
nohup python producer.py auto > /tmp/pbscan/pbscan_producer_7001.out &
nohup python consumer.py burp 8083  > /tmp/pbscan/pbscan_consumer_8083.out &
