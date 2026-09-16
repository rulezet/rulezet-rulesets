rule TTP_XOR_QUAD_CurrentVersionRun_e4df {
  strings:
    $key_e4df = { b7 b0 [2] 93 be [2] b8 92 [2] 96 b0 [2] 82 ab [2] 8d b1 [2] 93 ac [2] 91 ad [2] 8a ab [2] 96 ac [2] 8a 83 }

  condition:
    any of them
}