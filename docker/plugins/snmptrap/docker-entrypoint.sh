#!/bin/bash

echo \
"---
server: http://${SNOOZE_SERVER}:5200" \
> /etc/snooze/client.yaml

/opt/snooze/bin/snooze-snmptrap
