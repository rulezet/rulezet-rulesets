rule Virus_Injector_Generic_Viking_EBBC447A {
  meta:
    description = "datamaliciousorder - file Virus.Injector_Generic.Viking.EBBC447A.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "05b6b42df0a402f2cf21d1d67851610f9e9fd75aa624415ffd8025b9f92cfa6a"

  strings:
    $s1  = "and the Indy Pit Crew - http://www.nevrona.com/Indy/" fullword ascii
    $s2  = "* The _ character gets translated to - to avoid DNS name problems." fullword ascii
    $s3  = "COMPNAME [/c name | /d [template] | /s]" fullword ascii
    $s4  = "* This program does not rename the computer's domain account." fullword ascii
    $s5  = "Portions of this software are Copyright (c) 1993 - 2002, Chad Z. Hower (Kudzu)" fullword ascii
    $s6  = "* You can simply replace a /c switch with a /d switch to check the name." fullword ascii
    $s7  = "COMPNAME /s           Displays system summary information." fullword ascii
    $s8  = "COMPNAME /d ?s        Displays the system serial number." fullword ascii
    $s9  = "RCode NO Error%DNS Server Reports Query Format Error%DNS Server Reports Query Server Error#DNS Server Reports Query Name Error.D" wide
    $s10 = "?d = Hostname found by reverse DNS lookup of IP address." fullword ascii
    $s11 = "* If the name (after macro expansion) is longer than 15 characters," fullword ascii
    $s12 = "Invalid Header Id %d3Received Packet is too small. Less than 12 bytes %d Received Packet is too small. %d" fullword wide
    $s13 = "Temperature Probe" fullword ascii
    $s14 = "The following macros are valid in the name or template." fullword ascii
    $s15 = "Cannot map physical memory to process memory!" fullword ascii
    $s16 = "Failed to get data for '%s'%List does not allow duplicates ($0%x)" fullword wide
    $s17 = "Pipeline Burst" fullword ascii
    $s18 = "System Version=" fullword ascii
    $s19 = "COMPNAME /c jupiter   Changes computer name to \"jupiter\"." fullword ascii
    $s20 = "Driver Version=%s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}