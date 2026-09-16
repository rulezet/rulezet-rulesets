rule SpicyHotPot_DvLayout {
   meta:
      description = "SpicyHotPot - DvLayout.exe: Used to identify rootkit installation component"
      author = "jai-minton"
      reference = "https://www.crowdstrike.com/blog/author/jai-minton/"
      copyright = "(c) 2020 CrowdStrike Inc."
      date = "2020-11-01"
      hash1 = "551c4564d5ff537572fd356fe96df7c45bf62de9351fae5bb4e6f81dcbe34ae5"
   strings:
      $x1 = "KMDF_LOOK.sys" fullword ascii
      $x2 = "KMDF_Protect.sys" fullword ascii
      $x3 = "StartService Error, errorode is : %d ." fullword ascii
      $x4 = "Software\\Microsoft\\%s\\st" fullword wide
      $s1 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s2 = "@api-ms-win-core-synch-l1-2-0.dll" fullword wide
      $s3 = "Genealogy.ini" fullword wide
      $s4 = "powercfg /h off" fullword ascii
      $s5 = " Type Descriptor'" fullword ascii
      $s6 = "find %s failed , errorcode : %d" fullword ascii
      $s7 = "find %s failed , errorcode : %d" fullword ascii
      $s8 = "Delete %s failed , errorcode : %d" fullword wide
      $s9 = "Delete %s failed , errorcode : %d" fullword wide
      $s10 = "OpenService failed , errorcode : %d" fullword wide
      $s11 = "&Beijing JoinHope Image Technology Ltd.1/0-" fullword ascii
      $s12 = "/c del /q %s" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and 1 of ($x*) and 5 of ($s*)
}