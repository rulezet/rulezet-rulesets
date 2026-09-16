rule SUSP_XORed_MSDOS_Stub_Message {
   meta:
      description = "Detects suspicious XORed MSDOS stub message"
      author = "Florian Roth"
      reference = "https://yara.readthedocs.io/en/latest/writingrules.html#xor-strings"
      date = "2019-10-28"
      modified = "2023-10-11"
      score = 55
      id = "9ab52434-9162-5fd5-bf34-8b163f6aeec4"
   strings:
      $xo1 = "This program cannot be run in DOS mode" xor(0x01-0xff) ascii wide
      $xo2 = "This program must be run under Win32" xor(0x01-0xff) ascii wide

      $fp1 = "AVAST Software" fullword wide ascii
      $fp2 = "AVG Netherlands" fullword wide ascii
      $fp3 = "AVG Technologies" ascii wide
      $fp4 = "Malicious Software Removal Tool" wide
      $fp5 = "McAfee Labs" fullword ascii wide
      $fp6 = "Kaspersky Lab" fullword ascii wide
      $fp7 = "<propertiesmap>" ascii wide  
      $fp10 = "Avira Engine Module" wide 
      $fp11 = "syntevo GmbH" wide fullword 
      $fp13 = "SophosClean" ascii 
      $fp14 = "SophosHomeClean" wide
   condition:
      1 of ($x*)
      and not 1 of ($fp*)
      and not uint16(0) == 0xb0b0       and not uint16(0) == 0x5953 }