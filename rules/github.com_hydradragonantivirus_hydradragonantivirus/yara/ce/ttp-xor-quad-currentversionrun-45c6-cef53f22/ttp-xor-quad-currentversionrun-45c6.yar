rule TTP_XOR_QUAD_CurrentVersionRun_45c6 {
  strings:
    $key_45c6 = { 16 a9 [2] 32 a7 [2] 19 8b [2] 37 a9 [2] 23 b2 [2] 2c a8 [2] 32 b5 [2] 30 b4 [2] 2b b2 [2] 37 b5 [2] 2b 9a }

  condition:
    any of them
}