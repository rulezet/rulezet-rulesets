rule TTP_XOR_QUAD_CurrentVersionRun_14df {
  strings:
    $key_14df = { 47 b0 [2] 63 be [2] 48 92 [2] 66 b0 [2] 72 ab [2] 7d b1 [2] 63 ac [2] 61 ad [2] 7a ab [2] 66 ac [2] 7a 83 }

  condition:
    any of them
}