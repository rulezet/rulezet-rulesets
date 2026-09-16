rule Waterbear_2_Jun17_RID2D33 : DEMO EXE FILE MAL {
   meta:
      description = "Detects malware from Operation Waterbear"
      author = "Florian Roth"
      reference = "https://www.trendmicro.com/en_us/research/17/f/following-trail-blacktech-cyber-espionage-campaigns.html"
      date = "2017-06-23 10:21:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "dcb5c350af76c590002a8ea00b01d862b4d89cccbec3908bfe92fdf25eaa6ea4"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "downloading movie" fullword ascii
      $s2 = "name=\"test.exe\"/>" fullword ascii
      $s3 = "<description>Test Application</description>" fullword ascii
      $s4 = "UI look 2003" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 1000KB and all of them )
}