rule TTP_XOR_QUAD_CurrentVersionRun_4da5 {
  strings:
    $key_4da5 = { 1e ca [2] 3a c4 [2] 11 e8 [2] 3f ca [2] 2b d1 [2] 24 cb [2] 3a d6 [2] 38 d7 [2] 23 d1 [2] 3f d6 [2] 23 f9 }

  condition:
    any of them
}