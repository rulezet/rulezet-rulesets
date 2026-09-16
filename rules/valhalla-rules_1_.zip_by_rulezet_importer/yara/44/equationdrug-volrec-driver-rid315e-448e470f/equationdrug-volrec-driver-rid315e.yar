rule EquationDrug_VolRec_Driver_RID315E : APT DEMO {
   meta:
      description = "EquationDrug - Collector plugin for Volrec - msrstd.sys"
      author = "Florian Roth"
      reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
      date = "2015-03-11 13:19:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "msrstd.sys" fullword wide
      $s1 = "msrstd.pdb" fullword ascii
      $s2 = "msrstd driver" fullword wide
   condition: 
      all of them
}