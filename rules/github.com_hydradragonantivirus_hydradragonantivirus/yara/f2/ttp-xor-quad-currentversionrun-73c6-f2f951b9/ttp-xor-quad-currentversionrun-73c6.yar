rule TTP_XOR_QUAD_CurrentVersionRun_73c6 {
  strings:
    $key_73c6 = { 20 a9 [2] 04 a7 [2] 2f 8b [2] 01 a9 [2] 15 b2 [2] 1a a8 [2] 04 b5 [2] 06 b4 [2] 1d b2 [2] 01 b5 [2] 1d 9a }

  condition:
    any of them
}