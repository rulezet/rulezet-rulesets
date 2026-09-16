rule TTP_XOR_QUAD_CurrentVersionRun_77df {
  strings:
    $key_77df = { 24 b0 [2] 00 be [2] 2b 92 [2] 05 b0 [2] 11 ab [2] 1e b1 [2] 00 ac [2] 02 ad [2] 19 ab [2] 05 ac [2] 19 83 }

  condition:
    any of them
}