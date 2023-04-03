# ContackGen

ContackGen is a contexctual cyber-attack data generator for Weka.

## Table of contents

- [ContackGen](#contackgen)
  - [Table of contents](#table-of-contents)
  - [Backend](#backend)
  - [Compile Weka](#compile-weka)
  - [Run GUI](#run-gui)
  - [What's next](#whats-next)
  - [Authors](#authors)

## Backend

ContackGen use a **Docker** backend to emulate the victim computer/server.

Available backend:

| Image name | Distribution | Active servicies |
| --- | --- | --- |
| `fersuy/contackgen-ubuntu2204:1.1.0` | Ubuntu 22.04 | nginx |

## Compile Weka

```
mvn clean package -Dmaven.test.skip=true -Dmaven.javadoc.skip=true
```

## Run GUI

```
Run le main de la classe weka.gui.GUIChooser
```

## What's next

- [ ] Flag attack packets (Need to use an IDS to log traffic and detect attack packets)
- [X] Make simulation time configurable (simulation time = 180s)
  - [X] Run conteiner with a web server nging as process and a payload embedded in the container
  - [X] Set generator variables (duration, pcap full path, docker image)
  - [X] Execute the payload inside the container with duration and pcap full path as args (remote exec command in container)
  - [X] Cleaning code (add comments, add error handling, ...)
- [X] Add time epoch in the Weka dataset
- [X] Make possible to have string data in the Weka dataset
- [ ] Make our extension a plugin
- [ ] Design a new backend architecture, maybe with many containers that permit to have one container that capture traffic from the victim and another container that emulate the victim. That will permit to have a more realistic simulation with any type of docker images for the victim.

## Authors

- Mathieu SALLIOT
- Pierre BLAIS
- Luis RIBEIRO
- Benjamin ALONZO
