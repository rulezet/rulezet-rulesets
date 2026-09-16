rule TTP_XOR_QUAD_CurrentVersionRun_45c3 {
  strings:
    $key_45c3 = { 16 ac [2] 32 a2 [2] 19 8e [2] 37 ac [2] 23 b7 [2] 2c ad [2] 32 b0 [2] 30 b1 [2] 2b b7 [2] 37 b0 [2] 2b 9f }

  condition:
    any of them
}