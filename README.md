# crypto

# to generate channel
java -jar crypto.jar -g

**Channel 1983f14e-04a4-410d-89e3-0ba634ff3bf8 generated with password: ee577437-3bd6-4035-9868-c08db7777167**

# to encrypt file
java -jar crypto.jar -e -c 1983f14e-04a4-410d-89e3-0ba634ff3bf8 -f ```<filename>```

# to decrypt file
java -jar crypto.jar -d -c 1983f14e-04a4-410d-89e3-0ba634ff3bf8 -p ee577437-3bd6-4035-9868-c08db7777167 -f ```<filename>```
