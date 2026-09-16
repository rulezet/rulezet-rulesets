rule TTP_XOR_QUAD_CurrentVersionRun_4fc3 {
  strings:
    $key_4fc3 = { 1c ac [2] 38 a2 [2] 13 8e [2] 3d ac [2] 29 b7 [2] 26 ad [2] 38 b0 [2] 3a b1 [2] 21 b7 [2] 3d b0 [2] 21 9f }

  condition:
    any of them
}