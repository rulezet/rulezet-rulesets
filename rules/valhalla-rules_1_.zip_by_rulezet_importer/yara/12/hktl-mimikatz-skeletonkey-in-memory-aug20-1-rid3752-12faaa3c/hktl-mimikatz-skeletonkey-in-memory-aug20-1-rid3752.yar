rule HKTL_Mimikatz_SkeletonKey_in_memory_Aug20_1_RID3752 : DEMO HKTL S0002 T1003 T1098_004 T1134_005 T1547_008 T1550_002 T1550_003 {
   meta:
      description = "Detects Mimikatz SkeletonKey in Memory"
      author = "Florian Roth"
      reference = "https://twitter.com/sbousseaden/status/1292143504131600384?s=12"
      date = "2020-08-09 17:33:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, S0002, T1003, T1098_004, T1134_005, T1547_008, T1550_002, T1550_003"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = { 60 ba 4f ca c7 44 24 34 dc 46 6c 7a c7 44 24 38 03 3c 17 81 c7 44 24 3c 94 c0 3d f6 } 
   condition: 
      1 of them
}