rule TTP_XOR_QUAD_CurrentVersionRun_63df {
  strings:
    $key_63df = { 30 b0 [2] 14 be [2] 3f 92 [2] 11 b0 [2] 05 ab [2] 0a b1 [2] 14 ac [2] 16 ad [2] 0d ab [2] 11 ac [2] 0d 83 }

  condition:
    any of them
}