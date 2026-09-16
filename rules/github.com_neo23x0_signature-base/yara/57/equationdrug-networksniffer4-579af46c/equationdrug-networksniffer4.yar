rule EquationDrug_NetworkSniffer4 {
   meta:
      description = "EquationDrug - Network-sniffer/patcher - atmdkdrv.sys"
      author = "Florian Roth (Nextron Systems)"
      reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
      date = "2015/03/11"
      modified = "2023-01-06"
      hash = "cace40965f8600a24a2457f7792efba3bd84d9ba"
      id = "12bb1eb3-a14e-5616-bc7c-249c83f97035"
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