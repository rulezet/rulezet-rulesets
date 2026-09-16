rule TTP_XOR_QUAD_CurrentVersionRun_68b9 {
  strings:
    $key_68b9 = { 3b d6 [2] 1f d8 [2] 34 f4 [2] 1a d6 [2] 0e cd [2] 01 d7 [2] 1f ca [2] 1d cb [2] 06 cd [2] 1a ca [2] 06 e5 }

  condition:
    any of them
}