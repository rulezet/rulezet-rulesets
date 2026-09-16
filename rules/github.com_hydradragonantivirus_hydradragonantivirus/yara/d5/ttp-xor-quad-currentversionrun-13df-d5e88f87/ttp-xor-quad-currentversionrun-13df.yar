rule TTP_XOR_QUAD_CurrentVersionRun_13df {
  strings:
    $key_13df = { 40 b0 [2] 64 be [2] 4f 92 [2] 61 b0 [2] 75 ab [2] 7a b1 [2] 64 ac [2] 66 ad [2] 7d ab [2] 61 ac [2] 7d 83 }

  condition:
    any of them
}