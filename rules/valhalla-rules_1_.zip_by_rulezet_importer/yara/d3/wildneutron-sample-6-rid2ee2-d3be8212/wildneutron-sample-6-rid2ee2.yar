rule WildNeutron_Sample_6_RID2EE2 : APT DEMO EXE FILE {
   meta:
      description = "Wild Neutron APT Sample Rule"
      author = "Florian Roth"
      reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
      date = "2015-07-10 11:33:31"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "mshtaex.exe" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 310KB and all of them
}