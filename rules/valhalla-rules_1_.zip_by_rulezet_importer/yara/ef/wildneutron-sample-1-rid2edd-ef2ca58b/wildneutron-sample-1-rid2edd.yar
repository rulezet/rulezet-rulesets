rule WildNeutron_Sample_1_RID2EDD : APT DEMO EXE FILE {
   meta:
      description = "Wild Neutron APT Sample Rule"
      author = "Florian Roth"
      reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
      date = "2015-07-10 11:32:41"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "LiveUpdater.exe" fullword wide
      $s1 = "id-at-postalAddress" fullword ascii
      $s2 = "%d -> %d (default)" fullword wide
      $s3 = "%s%s%s=%d,%s=%d,%s=%d," fullword wide
      $s8 = "id-ce-keyUsage" fullword ascii
      $s9 = "Key Usage" fullword ascii
      $s32 = "UPDATE_ID" fullword wide
      $s37 = "id-at-commonName" fullword ascii
      $s38 = "2008R2" fullword wide
      $s39 = "RSA-alt" fullword ascii
      $s40 = "%02d.%04d.%s" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 800KB and all of them
}