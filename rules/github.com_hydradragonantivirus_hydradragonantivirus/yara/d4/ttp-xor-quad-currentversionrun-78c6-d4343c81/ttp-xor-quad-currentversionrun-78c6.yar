rule TTP_XOR_QUAD_CurrentVersionRun_78c6 {
  strings:
    $key_78c6 = { 2b a9 [2] 0f a7 [2] 24 8b [2] 0a a9 [2] 1e b2 [2] 11 a8 [2] 0f b5 [2] 0d b4 [2] 16 b2 [2] 0a b5 [2] 16 9a }

  condition:
    any of them
}