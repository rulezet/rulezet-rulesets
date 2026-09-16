rule TTP_XOR_QUAD_CurrentVersionRun_03df {
  strings:
    $key_03df = { 50 b0 [2] 74 be [2] 5f 92 [2] 71 b0 [2] 65 ab [2] 6a b1 [2] 74 ac [2] 76 ad [2] 6d ab [2] 71 ac [2] 6d 83 }

  condition:
    any of them
}