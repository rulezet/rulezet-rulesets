rule TTP_XOR_QUAD_CurrentVersionRun_15c3 {
  strings:
    $key_15c3 = { 46 ac [2] 62 a2 [2] 49 8e [2] 67 ac [2] 73 b7 [2] 7c ad [2] 62 b0 [2] 60 b1 [2] 7b b7 [2] 67 b0 [2] 7b 9f }

  condition:
    any of them
}