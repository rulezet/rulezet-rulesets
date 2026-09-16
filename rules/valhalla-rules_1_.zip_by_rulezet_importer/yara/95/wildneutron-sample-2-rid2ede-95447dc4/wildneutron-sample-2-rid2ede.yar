rule WildNeutron_Sample_2_RID2EDE : APT DEMO EXE FILE T1218_011 {
   meta:
      description = "Wild Neutron APT Sample Rule"
      author = "Florian Roth"
      reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
      date = "2015-07-10 11:32:51"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, EXE, FILE, T1218_011"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "rundll32.exe \"%s\",#1" fullword wide
      $s1 = "IgfxUpt.exe" fullword wide
      $s2 = "id-at-postalAddress" fullword ascii
      $s3 = "Intel(R) Common User Interface" fullword wide
      $s4 = "%s%s%s=%d,%s=%d,%s=%d," fullword wide
      $s11 = "Key Usage" fullword ascii
      $s12 = "Intel Integrated Graphics Updater" fullword wide
      $s13 = "%sexpires on    : %04d-%02d-%02d %02d:%02d:%02d" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 600KB and all of them
}