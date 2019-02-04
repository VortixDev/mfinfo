# mfinfo
A tool for reading information from a MIFARE device.

Doesn't take any parameters.

Currently, the tool will print the device's ATQA, UID, SAK, and ATS (if it has one). It will also identify if the card is a generation 1 magic card, and can provide the most likely card type based off of the SAK and ATS.

Requires `libnfc`.

