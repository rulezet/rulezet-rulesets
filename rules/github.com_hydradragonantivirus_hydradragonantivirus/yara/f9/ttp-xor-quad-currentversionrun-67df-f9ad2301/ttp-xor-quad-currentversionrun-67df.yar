rule TTP_XOR_QUAD_CurrentVersionRun_67df {
  strings:
    $key_67df = { 34 b0 [2] 10 be [2] 3b 92 [2] 15 b0 [2] 01 ab [2] 0e b1 [2] 10 ac [2] 12 ad [2] 09 ab [2] 15 ac [2] 09 83 }

  condition:
    any of them
}