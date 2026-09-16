rule Waterbear_6_Jun17_RID2D37 : DEMO EXE FILE MAL {
   meta:
      description = "Detects malware from Operation Waterbear"
      author = "Florian Roth"
      reference = "https://www.trendmicro.com/en_us/research/17/f/following-trail-blacktech-cyber-espionage-campaigns.html"
      date = "2017-06-23 10:22:21"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "409cd490feb40d08eb33808b78d52c00e1722eee163b60635df6c6fe2c43c230"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "svcdll.dll" fullword ascii
      $s2 = "log.log" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 60KB and all of them )
}