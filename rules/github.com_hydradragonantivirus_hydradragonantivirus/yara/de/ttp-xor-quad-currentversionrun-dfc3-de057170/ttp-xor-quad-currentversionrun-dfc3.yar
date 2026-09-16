rule TTP_XOR_QUAD_CurrentVersionRun_dfc3 {
  strings:
    $key_dfc3 = { 8c ac [2] a8 a2 [2] 83 8e [2] ad ac [2] b9 b7 [2] b6 ad [2] a8 b0 [2] aa b1 [2] b1 b7 [2] ad b0 [2] b1 9f }

  condition:
    any of them
}