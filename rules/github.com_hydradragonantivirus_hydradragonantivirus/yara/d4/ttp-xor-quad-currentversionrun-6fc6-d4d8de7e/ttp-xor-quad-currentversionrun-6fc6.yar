rule TTP_XOR_QUAD_CurrentVersionRun_6fc6 {
  strings:
    $key_6fc6 = { 3c a9 [2] 18 a7 [2] 33 8b [2] 1d a9 [2] 09 b2 [2] 06 a8 [2] 18 b5 [2] 1a b4 [2] 01 b2 [2] 1d b5 [2] 01 9a }

  condition:
    any of them
}