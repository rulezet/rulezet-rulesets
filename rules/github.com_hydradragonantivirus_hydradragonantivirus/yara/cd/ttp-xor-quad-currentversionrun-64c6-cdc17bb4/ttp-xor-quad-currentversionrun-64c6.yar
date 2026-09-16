rule TTP_XOR_QUAD_CurrentVersionRun_64c6 {
  strings:
    $key_64c6 = { 37 a9 [2] 13 a7 [2] 38 8b [2] 16 a9 [2] 02 b2 [2] 0d a8 [2] 13 b5 [2] 11 b4 [2] 0a b2 [2] 16 b5 [2] 0a 9a }

  condition:
    any of them
}