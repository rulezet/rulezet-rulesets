rule EquationDrug_NetworkSniffer5_RID3234 : APT DEMO T1040 {
   meta:
      description = "EquationDrug - Network-sniffer/patcher - atmdkdrv.sys"
      author = "Florian Roth"
      reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
      date = "2015-03-11 13:55:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-01-06"
      tags = "APT, DEMO, T1040"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Microsoft(R) Windows (TM) Operating System" fullword wide
      $s1 = "\\Registry\\User\\CurrentUser\\" wide
      $s2 = "atmdkdrv.sys" fullword wide
      $s4 = "\\Device\\%ws_%ws" wide
      $s5 = "\\DosDevices\\%ws" wide
      $s6 = "\\Device\\%ws" wide
   condition: 
      all of them
}