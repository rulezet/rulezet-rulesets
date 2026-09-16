rule TTP_XOR_QUAD_CurrentVersionRun_60d6 {
  strings:
    $key_60d6 = { 33 b9 [2] 17 b7 [2] 3c 9b [2] 12 b9 [2] 06 a2 [2] 09 b8 [2] 17 a5 [2] 15 a4 [2] 0e a2 [2] 12 a5 [2] 0e 8a }

  condition:
    any of them
}