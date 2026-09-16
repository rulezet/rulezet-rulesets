rule TTP_XOR_QUAD_CurrentVersionRun_4bba {
  strings:
    $key_4bba = { 18 d5 [2] 3c db [2] 17 f7 [2] 39 d5 [2] 2d ce [2] 22 d4 [2] 3c c9 [2] 3e c8 [2] 25 ce [2] 39 c9 [2] 25 e6 }

  condition:
    any of them
}