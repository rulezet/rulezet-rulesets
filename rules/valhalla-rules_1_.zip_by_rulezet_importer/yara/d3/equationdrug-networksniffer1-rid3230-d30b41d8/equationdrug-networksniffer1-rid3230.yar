rule EquationDrug_NetworkSniffer1_RID3230 : APT DEMO T1040 {
   meta:
      description = "EquationDrug - Backdoor driven by network sniffer - mstcp32.sys, fat32.sys"
      author = "Florian Roth"
      reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
      date = "2015-03-11 13:54:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-01-06"
      tags = "APT, DEMO, T1040"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Microsoft(R) Windows (TM) Operating System" fullword wide
      $s1 = "\\Registry\\User\\CurrentUser\\" wide
      $s3 = "sys\\mstcp32.dbg" fullword ascii
      $s7 = "mstcp32.sys" fullword wide
      $s8 = "p32.sys" fullword ascii
      $s9 = "\\Device\\%ws_%ws" wide
      $s10 = "\\DosDevices\\%ws" wide
      $s11 = "\\Device\\%ws" wide
   condition: 
      all of them
}