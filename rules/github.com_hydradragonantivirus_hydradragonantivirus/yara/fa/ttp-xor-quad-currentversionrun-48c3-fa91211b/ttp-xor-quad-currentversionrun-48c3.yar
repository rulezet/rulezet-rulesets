rule TTP_XOR_QUAD_CurrentVersionRun_48c3 {
  strings:
    $key_48c3 = { 1b ac [2] 3f a2 [2] 14 8e [2] 3a ac [2] 2e b7 [2] 21 ad [2] 3f b0 [2] 3d b1 [2] 26 b7 [2] 3a b0 [2] 26 9f }

  condition:
    any of them
}