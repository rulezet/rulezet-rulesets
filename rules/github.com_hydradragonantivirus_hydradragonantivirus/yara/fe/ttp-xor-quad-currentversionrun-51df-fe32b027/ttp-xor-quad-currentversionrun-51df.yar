rule TTP_XOR_QUAD_CurrentVersionRun_51df {
  strings:
    $key_51df = { 02 b0 [2] 26 be [2] 0d 92 [2] 23 b0 [2] 37 ab [2] 38 b1 [2] 26 ac [2] 24 ad [2] 3f ab [2] 23 ac [2] 3f 83 }

  condition:
    any of them
}