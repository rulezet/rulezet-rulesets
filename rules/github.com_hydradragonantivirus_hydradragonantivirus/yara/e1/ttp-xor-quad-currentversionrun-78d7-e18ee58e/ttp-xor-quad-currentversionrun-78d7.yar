rule TTP_XOR_QUAD_CurrentVersionRun_78d7 {
  strings:
    $key_78d7 = { 2b b8 [2] 0f b6 [2] 24 9a [2] 0a b8 [2] 1e a3 [2] 11 b9 [2] 0f a4 [2] 0d a5 [2] 16 a3 [2] 0a a4 [2] 16 8b }

  condition:
    any of them
}