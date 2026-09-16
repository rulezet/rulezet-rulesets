rule Waterbear_8_Jun17_RID2D39 : DEMO EXE FILE MAL T1543_003 {
   meta:
      description = "Detects malware from Operation Waterbear"
      author = "Florian Roth"
      reference = "https://www.trendmicro.com/en_us/research/17/f/following-trail-blacktech-cyber-espionage-campaigns.html"
      date = "2017-06-23 10:22:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "bd06f6117a0abf1442826179f6f5e1932047b4a6c14add9149e8288ab4a902c3"
      hash2 = "5dba8ddf05cb204ef320a72a0c031e55285202570d7883f2ff65135ec35b3dd0"
      tags = "DEMO, EXE, FILE, MAL, T1543_003"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Update.dll" fullword ascii
      $s2 = "ADVPACK32.DLL" fullword wide
      $s3 = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\" ascii
      $s4 = "\\drivers\\sftst.sys" ascii
      $s5 = "\\\\.\\SFilter" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 40KB and all of them )
}