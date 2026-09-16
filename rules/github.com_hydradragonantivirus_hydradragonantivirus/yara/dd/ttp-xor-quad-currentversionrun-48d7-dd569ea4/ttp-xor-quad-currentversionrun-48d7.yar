rule TTP_XOR_QUAD_CurrentVersionRun_48d7 {
  strings:
    $key_48d7 = { 1b b8 [2] 3f b6 [2] 14 9a [2] 3a b8 [2] 2e a3 [2] 21 b9 [2] 3f a4 [2] 3d a5 [2] 26 a3 [2] 3a a4 [2] 26 8b }

  condition:
    any of them
}