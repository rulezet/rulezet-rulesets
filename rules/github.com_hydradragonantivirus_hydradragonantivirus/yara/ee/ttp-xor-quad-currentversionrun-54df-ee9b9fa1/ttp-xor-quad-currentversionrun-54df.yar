rule TTP_XOR_QUAD_CurrentVersionRun_54df {
  strings:
    $key_54df = { 07 b0 [2] 23 be [2] 08 92 [2] 26 b0 [2] 32 ab [2] 3d b1 [2] 23 ac [2] 21 ad [2] 3a ab [2] 26 ac [2] 3a 83 }

  condition:
    any of them
}