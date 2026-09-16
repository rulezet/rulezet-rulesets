rule EXPL_LNX_DirtyFragLPE_May26_RID3055 : DEMO EXPLOIT FILE LINUX T1068 {
   meta:
      description = "Detects dirtyfrag, a local privilege escalation exploit for Linux."
      author = "Pezier Pierre-Henri"
      reference = "https://github.com/V4bel/dirtyfrag/tree/master"
      date = "2026-05-07 12:35:21"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXPLOIT, FILE, LINUX, T1068"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "gained CAP_NET_RAW within netn" ascii
      $x2 = "DIRTYFRAG_VERBOSE" ascii
      $s1 = { 15 7C 4A 7F B9 79 37 9E } 
      $s2 = "/proc/self/setgroups" ascii fullword
      $s3 = "pcbc(fcrypt)" ascii fullword
      $s4 = { 17 bb c7 f3 3f 36 ba 71 8e 97 65 60 69 b6 f6 e6 } 
   condition: 
      filesize < 100KB and uint32be ( 0 ) == 0x7f454c46 and ( 1 of ( $x* ) or 3 of ( $s* ) )
}