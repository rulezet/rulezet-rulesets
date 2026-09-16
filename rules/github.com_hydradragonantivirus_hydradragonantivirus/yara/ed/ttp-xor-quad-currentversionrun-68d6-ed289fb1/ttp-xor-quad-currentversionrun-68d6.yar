rule TTP_XOR_QUAD_CurrentVersionRun_68d6 {
  strings:
    $key_68d6 = { 3b b9 [2] 1f b7 [2] 34 9b [2] 1a b9 [2] 0e a2 [2] 01 b8 [2] 1f a5 [2] 1d a4 [2] 06 a2 [2] 1a a5 [2] 06 8a }

  condition:
    any of them
}