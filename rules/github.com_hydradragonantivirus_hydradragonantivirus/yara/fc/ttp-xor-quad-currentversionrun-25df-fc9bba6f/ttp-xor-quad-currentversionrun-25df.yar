rule TTP_XOR_QUAD_CurrentVersionRun_25df {
  strings:
    $key_25df = { 76 b0 [2] 52 be [2] 79 92 [2] 57 b0 [2] 43 ab [2] 4c b1 [2] 52 ac [2] 50 ad [2] 4b ab [2] 57 ac [2] 4b 83 }

  condition:
    any of them
}