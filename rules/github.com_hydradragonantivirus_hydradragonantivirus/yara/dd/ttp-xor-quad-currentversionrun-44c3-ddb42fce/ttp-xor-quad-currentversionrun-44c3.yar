rule TTP_XOR_QUAD_CurrentVersionRun_44c3 {
  strings:
    $key_44c3 = { 17 ac [2] 33 a2 [2] 18 8e [2] 36 ac [2] 22 b7 [2] 2d ad [2] 33 b0 [2] 31 b1 [2] 2a b7 [2] 36 b0 [2] 2a 9f }

  condition:
    any of them
}