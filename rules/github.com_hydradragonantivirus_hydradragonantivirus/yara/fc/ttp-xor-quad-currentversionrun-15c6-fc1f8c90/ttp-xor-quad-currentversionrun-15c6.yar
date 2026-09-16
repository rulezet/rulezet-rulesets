rule TTP_XOR_QUAD_CurrentVersionRun_15c6 {
  strings:
    $key_15c6 = { 46 a9 [2] 62 a7 [2] 49 8b [2] 67 a9 [2] 73 b2 [2] 7c a8 [2] 62 b5 [2] 60 b4 [2] 7b b2 [2] 67 b5 [2] 7b 9a }

  condition:
    any of them
}