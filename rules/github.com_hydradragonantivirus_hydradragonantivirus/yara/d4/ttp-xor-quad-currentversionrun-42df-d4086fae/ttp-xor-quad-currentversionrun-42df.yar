rule TTP_XOR_QUAD_CurrentVersionRun_42df {
  strings:
    $key_42df = { 11 b0 [2] 35 be [2] 1e 92 [2] 30 b0 [2] 24 ab [2] 2b b1 [2] 35 ac [2] 37 ad [2] 2c ab [2] 30 ac [2] 2c 83 }

  condition:
    any of them
}