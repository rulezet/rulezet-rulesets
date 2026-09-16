rule Waterbear_7_Jun17_RID2D38 : DEMO EXE FILE MAL {
   meta:
      description = "Detects malware from Operation Waterbear"
      author = "Florian Roth"
      reference = "https://www.trendmicro.com/en_us/research/17/f/following-trail-blacktech-cyber-espionage-campaigns.html"
      date = "2017-06-23 10:22:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "6891aa78524e442f4dda66dff51db9798e1f92e6fefcdf21eb870b05b0293134"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Bluthmon.exe" fullword wide
      $s2 = "Motomon.exe" fullword wide
      $s3 = "%d.%s%d%d%d" fullword ascii
      $s4 = "mywishes.hlp" fullword ascii
      $s5 = "filemon.rtf" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 80KB and all of them )
}