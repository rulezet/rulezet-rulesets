rule EquationDrug_NetworkSniffer4_RID3233 : APT DEMO T1040 {
   meta:
      description = "EquationDrug - Network-sniffer/patcher - atmdkdrv.sys"
      author = "Florian Roth"
      reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
      date = "2015-03-11 13:55:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-01-06"
      tags = "APT, DEMO, T1040"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Copyright 1999 RAVISENT Technologies Inc." fullword wide
      $s1 = "\\systemroot\\" ascii
      $s2 = "RAVISENT Technologies Inc." fullword wide
      $s3 = "Created by VIONA Development" fullword wide
      $s4 = "\\Registry\\User\\CurrentUser\\" wide
      $s5 = "\\device\\harddiskvolume" wide
      $s7 = "ATMDKDRV.SYS" fullword wide
      $s8 = "\\Device\\%ws_%ws" wide
      $s9 = "\\DosDevices\\%ws" wide
      $s10 = "CineMaster C 1.1 WDM Main Driver" fullword wide
      $s11 = "\\Device\\%ws" wide
      $s13 = "CineMaster C 1.1 WDM" fullword wide
   condition: 
      all of them
}