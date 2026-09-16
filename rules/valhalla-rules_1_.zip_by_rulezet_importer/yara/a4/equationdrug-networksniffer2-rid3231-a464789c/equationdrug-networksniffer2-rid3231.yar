rule EquationDrug_NetworkSniffer2_RID3231 : APT DEMO T1040 {
   meta:
      description = "EquationDrug - Network Sniffer - tdip.sys"
      author = "Florian Roth"
      reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
      date = "2015-03-11 13:54:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, T1040"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Microsoft(R) Windows (TM) Operating System" fullword wide
      $s1 = "IP Transport Driver" fullword wide
      $s2 = "tdip.sys" fullword wide
      $s3 = "sys\\tdip.dbg" fullword ascii
      $s4 = "dip.sys" fullword ascii
      $s5 = "\\Device\\%ws_%ws" wide
      $s6 = "\\DosDevices\\%ws" wide
      $s7 = "\\Device\\%ws" wide
   condition: 
      all of them
}