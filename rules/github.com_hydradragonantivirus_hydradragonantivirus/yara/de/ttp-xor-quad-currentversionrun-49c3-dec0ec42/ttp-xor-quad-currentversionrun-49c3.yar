rule TTP_XOR_QUAD_CurrentVersionRun_49c3 {
  strings:
    $key_49c3 = { 1a ac [2] 3e a2 [2] 15 8e [2] 3b ac [2] 2f b7 [2] 20 ad [2] 3e b0 [2] 3c b1 [2] 27 b7 [2] 3b b0 [2] 27 9f }

  condition:
    any of them
}