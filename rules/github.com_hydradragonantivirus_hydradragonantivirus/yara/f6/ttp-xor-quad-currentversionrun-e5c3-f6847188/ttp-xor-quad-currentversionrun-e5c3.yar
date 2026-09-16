rule TTP_XOR_QUAD_CurrentVersionRun_e5c3 {
  strings:
    $key_e5c3 = { b6 ac [2] 92 a2 [2] b9 8e [2] 97 ac [2] 83 b7 [2] 8c ad [2] 92 b0 [2] 90 b1 [2] 8b b7 [2] 97 b0 [2] 8b 9f }

  condition:
    any of them
}