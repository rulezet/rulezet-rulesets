rule EXPL_HKTL_LNX_DirtyFragShellcode_May26_RID3499 : DEMO EXPLOIT HKTL LINUX T1068 {
   meta:
      description = "Detects a shellcode observed in dirtyfrag, a local privilege escalation exploit for Linux."
      author = "Pezier Pierre-Henri"
      reference = "https://github.com/V4bel/dirtyfrag/tree/master"
      date = "2026-05-07 15:37:21"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXPLOIT, HKTL, LINUX, T1068"
      minimum_yara = "3.5.0"
      
   strings:
      $op1 = { 31 ff 31 f6 31 c0 b0 6a 0f 05 b0 69 0f 05 b0 74 0f 05 6a 00 48 [6] 50 48 89 e2 48 [6] 31 f6 6a 3b 58 0f 05 } 
   condition: 
      $op1
}