rule TTP_XOR_QUAD_CurrentVersionRun_04df {
  strings:
    $key_04df = { 57 b0 [2] 73 be [2] 58 92 [2] 76 b0 [2] 62 ab [2] 6d b1 [2] 73 ac [2] 71 ad [2] 6a ab [2] 76 ac [2] 6a 83 }

  condition:
    any of them
}