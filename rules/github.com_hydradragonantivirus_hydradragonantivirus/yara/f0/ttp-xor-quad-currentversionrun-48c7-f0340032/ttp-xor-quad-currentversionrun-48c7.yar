rule TTP_XOR_QUAD_CurrentVersionRun_48c7 {
  strings:
    $key_48c7 = { 1b a8 [2] 3f a6 [2] 14 8a [2] 3a a8 [2] 2e b3 [2] 21 a9 [2] 3f b4 [2] 3d b5 [2] 26 b3 [2] 3a b4 [2] 26 9b }

  condition:
    any of them
}