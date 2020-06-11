# Perec
This project is part of the forensics class from EURECOM.  
[B1] Write a (preferably python) Linux command-line tools to parse, extract, and visualize PE resources.

# Features & help
Perec uses lief library to extract PE resources or raw data to parse.

Those are the supported features :
- CURSOR : Save cursor files to directory
- BITMAP : Save bitmap files to directory
- ICON : Display information and save icon files to directory
- MENU : Display or Save menu files to directory
- DIALOG : Display or Save dialog files to directory
- STRING : Display or Save string files to directory
- RCDATA : Save rcdata files to directory
- MESSAGETABLE : Display or Save messagetable files to directory
- VERSION : Display or Save version files to directory
- MANIFEST : Display or Save manifest file to directory

# Usage
```
python3 perec.p -i <inputfile> -o <outputDir>  [option]  
-i <inputfile> : Input File  
-o <outputDir> : Output Directory  
-t : Display PE resources found  
-a : Display all PE resources supported by lief resources manager  
-f : Display file infos  
-s <ICON/DIALOG/VERSION/MANIFEST>: Display PE resource with the possibility to save it if -o was used before  
```

