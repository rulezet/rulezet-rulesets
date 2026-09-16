rule TTP_XOR_QUAD_CurrentVersionRun_34df {
  strings:
    $key_34df = { 67 b0 [2] 43 be [2] 68 92 [2] 46 b0 [2] 52 ab [2] 5d b1 [2] 43 ac [2] 41 ad [2] 5a ab [2] 46 ac [2] 5a 83 }

  condition:
    any of them
}