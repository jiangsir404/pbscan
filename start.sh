#!/bin/bash

python pbscan.py -auto=8083 -headless &

python pbscan.py -auto=8084 -headless &

python pbscan.py -auto=8085 -headless &

python producer.py -auto &

python consumer.py burp=8083 &