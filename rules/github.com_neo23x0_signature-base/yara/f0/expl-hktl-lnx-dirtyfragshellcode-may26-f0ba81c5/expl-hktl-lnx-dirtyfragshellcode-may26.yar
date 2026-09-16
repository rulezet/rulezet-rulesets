rule EXPL_HKTL_LNX_DirtyFragShellcode_May26 {
   meta:
      description = "Detects a shellcode observed in dirtyfrag, a local privilege escalation exploit for Linux."
      reference = "https://github.com/V4bel/dirtyfrag/tree/master"
      author = "Pezier Pierre-Henri (Nextron Systems)"
      date = "2026-05-07"
      score = 80
      hash = "a02ea2ba8108a9b7a997faa8808cfc55bb69af54e69178fa5aa1785681cf0ced"
      id = "c156da87-c029-5084-9cd3-a233fefdaf25"
   strings:
      $op1 = {
         31 ff              31 f6              31 c0              b0 6a              0f 05              b0 69              0f 05              b0 74              0f 05              6a 00              48 [6]             50                 48 89 e2           48 [6]             31 f6              6a 3b              58                 0f 05           }
   condition:
      $op1
}