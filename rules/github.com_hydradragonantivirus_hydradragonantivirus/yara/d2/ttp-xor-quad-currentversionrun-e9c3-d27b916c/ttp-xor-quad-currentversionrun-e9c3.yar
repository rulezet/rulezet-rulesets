rule TTP_XOR_QUAD_CurrentVersionRun_e9c3 {
  strings:
    $key_e9c3 = { ba ac [2] 9e a2 [2] b5 8e [2] 9b ac [2] 8f b7 [2] 80 ad [2] 9e b0 [2] 9c b1 [2] 87 b7 [2] 9b b0 [2] 87 9f }

  condition:
    any of them
}