rule TTP_XOR_QUAD_CurrentVersionRun_04c7 {
  strings:
    $key_04c7 = { 57 a8 [2] 73 a6 [2] 58 8a [2] 76 a8 [2] 62 b3 [2] 6d a9 [2] 73 b4 [2] 71 b5 [2] 6a b3 [2] 76 b4 [2] 6a 9b }

  condition:
    any of them
}