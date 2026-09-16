rule Waterbear_11_Jun17_RID2D63 : DEMO EXE FILE MAL {
   meta:
      description = "Detects malware from Operation Waterbear"
      author = "Florian Roth"
      reference = "https://www.trendmicro.com/en_us/research/17/f/following-trail-blacktech-cyber-espionage-campaigns.html"
      date = "2017-06-23 10:29:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "b046b2e2569636c2fc3683a0da8cfad25ff47bc304145be0f282a969c7397ae8"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "/Pages/%u.asp" fullword wide
      $s2 = "NVIDIA Corporation." fullword wide
      $s3 = "tqxbLc|fP_{eOY{eOX{eO" fullword ascii
      $s4 = "Copyright (C) 2005" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 1000KB and all of them )
}