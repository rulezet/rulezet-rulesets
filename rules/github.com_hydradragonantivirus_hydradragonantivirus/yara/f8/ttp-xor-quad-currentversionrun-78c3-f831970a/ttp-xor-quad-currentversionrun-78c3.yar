rule TTP_XOR_QUAD_CurrentVersionRun_78c3 {
  strings:
    $key_78c3 = { 2b ac [2] 0f a2 [2] 24 8e [2] 0a ac [2] 1e b7 [2] 11 ad [2] 0f b0 [2] 0d b1 [2] 16 b7 [2] 0a b0 [2] 16 9f }

  condition:
    any of them
}