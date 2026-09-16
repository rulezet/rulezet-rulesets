rule WildNeutron_Sample_9_RID2EE5 : APT DEMO EXE FILE {
   meta:
      description = "Wild Neutron APT Sample Rule"
      author = "Florian Roth"
      reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
      date = "2015-07-10 11:34:01"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-01-06"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "http://get.adobe.com/flashplayer/" wide
      $s4 = " Player Installer/Uninstaller" fullword wide
      $s5 = "Adobe Flash Plugin Updater" fullword wide
      $s6 = "uSOFTWARE\\Adobe" fullword wide
      $s11 = "2008R2" fullword wide
      $s12 = "%02d.%04d.%s" fullword wide
      $s13 = "%d -> %d" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 1477KB and all of them
}