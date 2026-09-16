rule TTP_XOR_QUAD_CurrentVersionRun_5fc3 {
  strings:
    $key_5fc3 = { 0c ac [2] 28 a2 [2] 03 8e [2] 2d ac [2] 39 b7 [2] 36 ad [2] 28 b0 [2] 2a b1 [2] 31 b7 [2] 2d b0 [2] 31 9f }

  condition:
    any of them
}