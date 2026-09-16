rule EquationDrug_NetworkSniffer3_RID3232 : APT DEMO T1040 {
   meta:
      description = "EquationDrug - Network Sniffer - tdip.sys"
      author = "Florian Roth"
      reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
      date = "2015-03-11 13:54:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, T1040"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Corporation. All rights reserved." fullword wide
      $s1 = "IP Transport Driver" fullword wide
      $s2 = "tdip.sys" fullword wide
      $s3 = "tdip.pdb" fullword ascii
   condition: 
      all of them
}