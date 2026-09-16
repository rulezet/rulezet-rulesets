rule Waterbear_9_Jun17_RID2D3A : DEMO EXE FILE MAL {
   meta:
      description = "Detects malware from Operation Waterbear"
      author = "Florian Roth"
      reference = "https://www.trendmicro.com/en_us/research/17/f/following-trail-blacktech-cyber-espionage-campaigns.html"
      date = "2017-06-23 10:22:51"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "fc74d2434d48b316c9368d3f90fea19d76a20c09847421d1469268a32f59664c"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "ADVPACK32.DLL" fullword wide
      $s2 = "ADVPACK32" fullword wide
      $a1 = "U2_Dll.dll" fullword ascii
      $b1 = "ProUpdate" fullword ascii
      $b2 = "Update.dll" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 30KB and all of ( $s* ) and ( $a1 or all of ( $b* ) )
}