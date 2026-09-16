rule TTP_XOR_QUAD_CurrentVersionRun_c3df {
  strings:
    $key_c3df = { 90 b0 [2] b4 be [2] 9f 92 [2] b1 b0 [2] a5 ab [2] aa b1 [2] b4 ac [2] b6 ad [2] ad ab [2] b1 ac [2] ad 83 }

  condition:
    any of them
}