rule TTP_XOR_QUAD_CurrentVersionRun_14c3 {
  strings:
    $key_14c3 = { 47 ac [2] 63 a2 [2] 48 8e [2] 66 ac [2] 72 b7 [2] 7d ad [2] 63 b0 [2] 61 b1 [2] 7a b7 [2] 66 b0 [2] 7a 9f }

  condition:
    any of them
}