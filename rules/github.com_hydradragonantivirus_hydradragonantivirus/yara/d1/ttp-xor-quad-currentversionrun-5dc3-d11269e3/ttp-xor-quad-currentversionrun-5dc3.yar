rule TTP_XOR_QUAD_CurrentVersionRun_5dc3 {
  strings:
    $key_5dc3 = { 0e ac [2] 2a a2 [2] 01 8e [2] 2f ac [2] 3b b7 [2] 34 ad [2] 2a b0 [2] 28 b1 [2] 33 b7 [2] 2f b0 [2] 33 9f }

  condition:
    any of them
}