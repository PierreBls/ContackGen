# ContackGen

ContackGen is a contexctual cyber-attack data generator for Weka.

## Table of contents

- [ContackGen](#contackgen)
  - [Table of contents](#table-of-contents)
  - [Backend](#backend)
  - [Authors](#authors)

## Backend

ContackGen use a **Docker** backend to emulate the victim computer/server.

Available backend:

| Image name | Distribution | Active servicies |
| --- | --- | --- |
| `fersuy/contackgen-ubuntu2204:1.0.0` | Ubuntu 22.04 | None |

## Compile Weka

```
mvn clean package -Dmaven.test.skip=true -Dmaven.javadoc.skip=true
```

## Run GUI

```
Run le main de la classe weka.gui.GUIChooser
```

## Authors

- Mathieu SALLIOT
- Pierre BLAIS
- Luis RIBEIRO
- Benjamin ALONZO
