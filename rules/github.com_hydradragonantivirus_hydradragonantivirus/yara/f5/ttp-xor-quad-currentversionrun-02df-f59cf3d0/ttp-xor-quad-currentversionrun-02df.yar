rule TTP_XOR_QUAD_CurrentVersionRun_02df {
  strings:
    $key_02df = { 51 b0 [2] 75 be [2] 5e 92 [2] 70 b0 [2] 64 ab [2] 6b b1 [2] 75 ac [2] 77 ad [2] 6c ab [2] 70 ac [2] 6c 83 }

  condition:
    any of them
}