rule TTP_XOR_QUAD_CurrentVersionRun_68c6 {
  strings:
    $key_68c6 = { 3b a9 [2] 1f a7 [2] 34 8b [2] 1a a9 [2] 0e b2 [2] 01 a8 [2] 1f b5 [2] 1d b4 [2] 06 b2 [2] 1a b5 [2] 06 9a }

  condition:
    any of them
}