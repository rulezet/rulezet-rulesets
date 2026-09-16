rule TTP_XOR_QUAD_CurrentVersionRun_0ac3 {
  strings:
    $key_0ac3 = { 59 ac [2] 7d a2 [2] 56 8e [2] 78 ac [2] 6c b7 [2] 63 ad [2] 7d b0 [2] 7f b1 [2] 64 b7 [2] 78 b0 [2] 64 9f }

  condition:
    any of them
}