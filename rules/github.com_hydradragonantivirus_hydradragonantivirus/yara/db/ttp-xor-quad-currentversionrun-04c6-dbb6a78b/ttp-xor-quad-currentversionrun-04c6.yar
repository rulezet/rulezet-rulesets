rule TTP_XOR_QUAD_CurrentVersionRun_04c6 {
  strings:
    $key_04c6 = { 57 a9 [2] 73 a7 [2] 58 8b [2] 76 a9 [2] 62 b2 [2] 6d a8 [2] 73 b5 [2] 71 b4 [2] 6a b2 [2] 76 b5 [2] 6a 9a }

  condition:
    any of them
}