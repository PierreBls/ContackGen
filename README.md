# ContackGen
Contexctual Attack Data Generator for Weka

## TODO

1. Pull the docker image from DockerHub

```bash
docker pull fersuy/contackgen/ubuntu:22.04
```

2. Start the conateiner (60s scan start)

```bash
docker run --rm --name contackgen-ubuntu  fersuy/contackgen/ubuntu:22.04
```

3. Get the IP addres 
   
```bash
sudo docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' contackgen-ubuntu
```

4. Start Ddos attack
5. After 60s, pcap file is written. We can copy it:

```bash
docker cp contackgen-ubuntu:/data/capture.pcap ./capture.pcap
```
6. Cast `pcap` file and send it to weka.
