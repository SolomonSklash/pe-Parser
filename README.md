# peParser
A lightweight utility for parsing PE file formats (EXE, DLL, SYS)


### Usage

```
peParser:       A utility for parsing PE files formats and structures
Example:        peParser.exe /OVERVIEW <file.exe>

        Usage           Description
        -----           -----------------------------------------------------------------
        /OVERVIEW       List file properties and summary information
        /HEADERS        List PE header structure's information
        /IMPORTS        List IAT information, DLL and function imports
        /EXPORTS        List EAT information, export related functions
        /SECTIONS       List section related information
```

### /OVERVIEW

### /HEADERS

```
c:\peParser>peParser.exe /HEADERS calc.exe

----------------- Dos Header -----------------

Value           Member          Description

0x5a4d          e_magic         Magic Bytes
0x90            e_cblp          Bytes on last page of file
0x3             e_cp            Pages in file
0x0             e_crlc          Relocations
0x4             e_cparhdr       Size of header in paragraphsn
0x0             e_minalloc      Minimum extra paragraphs needed
0xffff          e_maxalloc      Maximum extra paragraphs needed
0x0             e_ss            Initial (relative) SS value
0xb8            e_sp            Initial SP value
0x0             e_csum          Checksum
0x0             e_ip            Initial IP value
0x0             e_cs            Initial (relative) CS value
0x40            e_lfarlc        File address of relocation table
0x0             e_ovno          Overlay number
0xbef004        e_lfanew        File address of new exe header

----------------- NT Headers -----------------

Value           Member          Description

0x4550          Signature       e_res2
...
```

### /IMPORTS

### /EXPORTS

### /SECTIONS
