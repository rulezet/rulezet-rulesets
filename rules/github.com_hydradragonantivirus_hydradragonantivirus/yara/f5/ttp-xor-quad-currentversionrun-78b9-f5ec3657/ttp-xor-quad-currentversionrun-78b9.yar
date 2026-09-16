rule TTP_XOR_QUAD_CurrentVersionRun_78b9 {
  strings:
    $key_78b9 = { 2b d6 [2] 0f d8 [2] 24 f4 [2] 0a d6 [2] 1e cd [2] 11 d7 [2] 0f ca [2] 0d cb [2] 16 cd [2] 0a ca [2] 16 e5 }

  condition:
    any of them
}