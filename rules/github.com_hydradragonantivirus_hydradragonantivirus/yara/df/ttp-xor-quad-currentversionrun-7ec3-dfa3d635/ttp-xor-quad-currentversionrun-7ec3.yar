rule TTP_XOR_QUAD_CurrentVersionRun_7ec3 {
  strings:
    $key_7ec3 = { 2d ac [2] 09 a2 [2] 22 8e [2] 0c ac [2] 18 b7 [2] 17 ad [2] 09 b0 [2] 0b b1 [2] 10 b7 [2] 0c b0 [2] 10 9f }

  condition:
    any of them
}