rule TTP_XOR_QUAD_CurrentVersionRun_7fc6 {
  strings:
    $key_7fc6 = { 2c a9 [2] 08 a7 [2] 23 8b [2] 0d a9 [2] 19 b2 [2] 16 a8 [2] 08 b5 [2] 0a b4 [2] 11 b2 [2] 0d b5 [2] 11 9a }

  condition:
    any of them
}