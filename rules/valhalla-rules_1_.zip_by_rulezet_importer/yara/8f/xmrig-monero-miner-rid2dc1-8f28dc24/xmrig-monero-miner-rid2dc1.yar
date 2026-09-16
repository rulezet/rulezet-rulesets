rule XMRIG_Monero_Miner_RID2DC1 : DEMO EXE FILE HIGHVOL SUSP xmrig {
   meta:
      description = "Detects Monero mining software"
      author = "Florian Roth"
      reference = "https://github.com/xmrig/xmrig/releases"
      date = "2018-01-04 10:45:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2022-11-10"
      hash1 = "5c13a274adb9590249546495446bb6be5f2a08f9dcd2fc8a2049d9dc471135c0"
      hash2 = "08b55f9b7dafc53dfc43f7f70cdd7048d231767745b76dc4474370fb323d7ae7"
      hash3 = "f3f2703a7959183b010d808521b531559650f6f347a5830e47f8e3831b10bad5"
      tags = "DEMO, EXE, FILE, HIGHVOL, SUSP, xmrig"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "'h' hashrate, 'p' pause, 'r' resume" fullword ascii
      $s2 = "--cpu-affinity" ascii
      $s3 = "set process affinity to CPU core(s), mask 0x3 for cores 0 and 1" ascii
      $s4 = "password for mining server" fullword ascii
      $s5 = "XMRig/%s libuv/%s%s" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d or uint16 ( 0 ) == 0x457f ) and filesize < 10MB and 2 of them
}