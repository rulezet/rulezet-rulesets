rule TTP_XOR_QUAD_CurrentVersionRun_58c3 {
  strings:
    $key_58c3 = { 0b ac [2] 2f a2 [2] 04 8e [2] 2a ac [2] 3e b7 [2] 31 ad [2] 2f b0 [2] 2d b1 [2] 36 b7 [2] 2a b0 [2] 36 9f }

  condition:
    any of them
}