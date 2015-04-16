# pynfdump-riemann-alerter

pynfdump-riemann-alerter
============

pynfdump-riemann-alerter is a quick (and dirty) script that performs netflow pynfdump queries based on a yaml configuration file. An alert is sent to riemann (http://riemann.io) when a threshold is reached.

the YAML configuration file must be named netflow-alerting.yaml and located in /etc (or you may edit it's path within the script).

Requirements
------------

You may install the requirements using the following commands:

```
pip install -a requirements.txt
```

Write right is required for the log file /var/log/netflow-alerting.log

The script has only been tested on Ubuntu but should work on most linux distro.
