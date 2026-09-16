rule TTP_XOR_QUAD_CurrentVersionRun_25c7 {
  strings:
    $key_25c7 = { 76 a8 [2] 52 a6 [2] 79 8a [2] 57 a8 [2] 43 b3 [2] 4c a9 [2] 52 b4 [2] 50 b5 [2] 4b b3 [2] 57 b4 [2] 4b 9b }

  condition:
    any of them
}