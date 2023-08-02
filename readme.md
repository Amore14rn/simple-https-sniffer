#### Run 
```bash
$ docker build -t sniffer .
$ docker run -it --net="host" --privileged sniffer /bin/bash
# sniffer list 
# sniffer run eth0
```
