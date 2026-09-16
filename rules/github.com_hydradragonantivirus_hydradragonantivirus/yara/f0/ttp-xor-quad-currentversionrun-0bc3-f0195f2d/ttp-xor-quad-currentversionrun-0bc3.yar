rule TTP_XOR_QUAD_CurrentVersionRun_0bc3 {
  strings:
    $key_0bc3 = { 58 ac [2] 7c a2 [2] 57 8e [2] 79 ac [2] 6d b7 [2] 62 ad [2] 7c b0 [2] 7e b1 [2] 65 b7 [2] 79 b0 [2] 65 9f }

  condition:
    any of them
}