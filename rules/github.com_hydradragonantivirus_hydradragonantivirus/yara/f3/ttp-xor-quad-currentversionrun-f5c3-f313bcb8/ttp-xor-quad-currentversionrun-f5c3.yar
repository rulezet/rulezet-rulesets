rule TTP_XOR_QUAD_CurrentVersionRun_f5c3 {
  strings:
    $key_f5c3 = { a6 ac [2] 82 a2 [2] a9 8e [2] 87 ac [2] 93 b7 [2] 9c ad [2] 82 b0 [2] 80 b1 [2] 9b b7 [2] 87 b0 [2] 9b 9f }

  condition:
    any of them
}