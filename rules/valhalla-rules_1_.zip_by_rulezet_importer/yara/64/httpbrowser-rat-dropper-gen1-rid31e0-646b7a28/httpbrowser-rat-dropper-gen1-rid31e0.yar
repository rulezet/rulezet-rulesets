rule HttpBrowser_RAT_dropper_Gen1_RID31E0 : APT DEMO EXE FILE G0027 T1574_001 {
   meta:
      description = "Threat Group 3390 APT Sample - HttpBrowser RAT Dropper"
      author = "Florian Roth"
      reference = "http://snip.ly/giNB"
      date = "2015-08-06 13:41:11"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "808de72f1eae29e3c1b2c32be1b84c5064865a235866edf5e790d2a7ba709907"
      hash2 = "f6f966d605c5e79de462a65df437ddfca0ad4eb5faba94fc875aba51a4b894a7"
      hash3 = "f424965a35477d822bbadb821125995616dc980d3d4f94a68c87d0cd9b291df9"
      tags = "APT, DEMO, EXE, FILE, G0027, T1574_001"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "1001=cmd.exe" fullword ascii
      $x2 = "1003=ShellExecuteA" fullword ascii
      $x3 = "1002=/c del /q %s" fullword ascii
      $x4 = "1004=SetThreadPriority" fullword ascii
      $op0 = { e8 71 11 00 00 83 c4 10 ff 4d e4 8b f0 78 07 8b } 
      $op1 = { e8 85 34 00 00 59 59 8b 86 b4 } 
      $op2 = { 8b 45 0c 83 38 00 0f 84 97 } 
      $op3 = { 8b 45 0c 83 38 00 0f 84 98 } 
      $op4 = { 89 7e 0c ff 15 a0 50 40 00 59 8b d8 6a 20 59 8d } 
      $op5 = { 56 8d 85 cd fc ff ff 53 50 88 9d cc fc ff ff e8 } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 400KB and all of ( $x* ) and 1 of ( $op* )
}