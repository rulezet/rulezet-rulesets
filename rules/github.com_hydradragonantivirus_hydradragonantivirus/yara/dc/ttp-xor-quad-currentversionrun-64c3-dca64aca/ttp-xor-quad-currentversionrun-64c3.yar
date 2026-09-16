rule TTP_XOR_QUAD_CurrentVersionRun_64c3 {
  strings:
    $key_64c3 = { 37 ac [2] 13 a2 [2] 38 8e [2] 16 ac [2] 02 b7 [2] 0d ad [2] 13 b0 [2] 11 b1 [2] 0a b7 [2] 16 b0 [2] 0a 9f }

  condition:
    any of them
}