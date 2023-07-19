## Simple Https Sniffer (CLI version)
It's a simple https sniffer (cli version) that I have made for [this task](task.md).

Links to repositories:
* https://bitbucket.org/alexmaker/simple-https-sniffer/
* https://github.com/Alexitdv/simple-https-sniffer

### Getting started
__eth0__ - Example of device name from __sniffer list__ command.

Clone repository from **bitbucket.org**
```bash
$ git clone git@bitbucket.org:alexmaker/simple-http-sniffer.git
```

Clone repository from **github.com**
```bash
$ git clone git@github.com:Alexitdv/simple-https-sniffer.git
```

#### Run 
```bash
$ docker build -t sniffer .
$ docker run -it --net="host" --privileged sniffer /bin/bash
# sniffer list 
# sniffer run eth0
```