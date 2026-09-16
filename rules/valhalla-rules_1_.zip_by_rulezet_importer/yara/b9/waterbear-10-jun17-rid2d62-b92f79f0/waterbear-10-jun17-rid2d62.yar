rule Waterbear_10_Jun17_RID2D62 : DEMO EXE FILE MAL {
   meta:
      description = "Detects malware from Operation Waterbear"
      author = "Florian Roth"
      reference = "https://www.trendmicro.com/en_us/research/17/f/following-trail-blacktech-cyber-espionage-campaigns.html"
      date = "2017-06-23 10:29:31"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "3b1e67e0e86d912d7bc6dee5b0f801260350e8ce831c93c3e9cfe5a39e766f41"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "ADVPACK32.DLL" fullword wide
      $s5 = "ADVPACK32" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 30KB and all of them )
}