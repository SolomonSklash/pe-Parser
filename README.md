# peParser
A lightweight utility for parsing PE file formats (EXE, DLL, SYS). Windows Portable Executable (PE) files includes a variety of parsable data structures. This utility takes a PE file as a CLI argument and parses the various structures and aspects of file information.

To learn more about the Windows PE file format I recommend the `Life of Binaries` training by OpenSecurityTraining [here](https://www.youtube.com/watch?v=ls8I__h1IYE&list=PLUFkSN0XLZ-n_Na6jwqopTt1Ki57vMIc3)

Read my blog post that discusses the PE format and how to parse it [here](https://fullpwnops.com/pe-file-parsing-manual-injection/)

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

Get a quick overview of the provided PE file, hashes for the file, sections, and other file information

```
c:\peParser>peParser.exe /OVERVIEW calc.exe

----------------- File Information -----------------

File name:       calc.exe
File size:       27648 Kb
Creation Date:   2021-10-15 17:36:23
```

### /HEADERS

Parse PE file structures relating to headers

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

Get a listing of API function imports and their associated DLL library

### /EXPORTS

Get a listing of exported API functions

### /SECTIONS

Get information about the PE's sections

```
----------------- Section Headers -----------------

SECTION HEADER #0
        .text
                Virtual Size: 0xbd0
                Virtual Address: 0x1000
                Raw Size: 0xc00
                Raw Address: 0x400
                Reloc Address: 0x0
                Relocations Number: 0x0
                Line Numbers: 0x0
                Characteristics: 0x60000020
SECTION HEADER #1
        .rdata
                Virtual Size: 0xc76
                Virtual Address: 0x2000
                Raw Size: 0xe00
                Raw Address: 0x1000
                Reloc Address: 0x0
                Relocations Number: 0x0
                Line Numbers: 0x0
                Characteristics: 0x40000040
SECTION HEADER #2
        .data
                Virtual Size: 0x6b8
                Virtual Address: 0x3000
                Raw Size: 0x200
                Raw Address: 0x1e00
                Reloc Address: 0x0
                Relocations Number: 0x0
                Line Numbers: 0x0
                Characteristics: 0xc0000040
...
```
