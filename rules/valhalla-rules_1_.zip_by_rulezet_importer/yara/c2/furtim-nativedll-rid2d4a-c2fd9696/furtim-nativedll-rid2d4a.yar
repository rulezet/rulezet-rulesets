rule Furtim_nativeDLL_RID2D4A : DEMO EXE FILE MAL {
   meta:
      description = "Detects Furtim malware - file native.dll"
      author = "Florian Roth"
      reference = "MISP 3971"
      date = "2016-06-13 10:25:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "4f39d3e70ed1278d5fa83ed9f148ca92383ec662ac34635f7e56cc42eeaee948"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "FqkVpTvBwTrhPFjfFF6ZQRK44hHl26" fullword ascii
      $op0 = { e0 b3 42 00 c7 84 24 ac } 
      $op1 = { a1 e0 79 44 00 56 ff 90 10 01 00 00 a1 e0 79 44 } 
      $op2 = { bf d0 25 44 00 57 89 4d f0 ff 90 d4 02 00 00 59 } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 900KB and $s1 or all of ( $op* )
}