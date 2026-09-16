rule TTP_XOR_QUAD_CurrentVersionRun_7ac3 {
  strings:
    $key_7ac3 = { 29 ac [2] 0d a2 [2] 26 8e [2] 08 ac [2] 1c b7 [2] 13 ad [2] 0d b0 [2] 0f b1 [2] 14 b7 [2] 08 b0 [2] 14 9f }

  condition:
    any of them
}