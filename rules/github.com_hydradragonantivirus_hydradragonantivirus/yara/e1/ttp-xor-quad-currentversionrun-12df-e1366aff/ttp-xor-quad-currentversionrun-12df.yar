rule TTP_XOR_QUAD_CurrentVersionRun_12df {
  strings:
    $key_12df = { 41 b0 [2] 65 be [2] 4e 92 [2] 60 b0 [2] 74 ab [2] 7b b1 [2] 65 ac [2] 67 ad [2] 7c ab [2] 60 ac [2] 7c 83 }

  condition:
    any of them
}