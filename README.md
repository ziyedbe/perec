# Perec
This project is part of the forensics class from EURECOM.
[B1] Write a (preferably python) Linux command-line tools to parse, extract, and visualize PE resources.

# Features & help
Perec is able to extract and parse the PE resources using lief library.
Those are the supported features :
- Extracting and saving ICONs
- Extracting and saving Manifest file
- Extracting and saving DIALOGs
- Extracting and saving VERSIONINFO
- Extracting file infos

## Future additions
- BITMAP
- MENU
...

~
# Usage
-i <inputfile> : Input File
-o <outputfile> : Output File
-t : Display PE resources found
-a : Display all PE resources
-f : Display file infos
-s <ICON/DIALOG/VERSION/MANIFEST>: Display PE resource with the possibility to save it if -o was used before, for icons -o is mandatory to save the icons

