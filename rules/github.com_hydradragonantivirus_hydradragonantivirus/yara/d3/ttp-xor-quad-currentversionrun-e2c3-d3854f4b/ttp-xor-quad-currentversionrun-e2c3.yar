rule TTP_XOR_QUAD_CurrentVersionRun_e2c3 {
  strings:
    $key_e2c3 = { b1 ac [2] 95 a2 [2] be 8e [2] 90 ac [2] 84 b7 [2] 8b ad [2] 95 b0 [2] 97 b1 [2] 8c b7 [2] 90 b0 [2] 8c 9f }

  condition:
    any of them
}