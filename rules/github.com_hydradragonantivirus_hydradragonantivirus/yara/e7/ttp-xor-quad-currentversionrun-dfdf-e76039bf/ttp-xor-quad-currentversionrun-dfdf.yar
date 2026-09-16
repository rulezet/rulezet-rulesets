rule TTP_XOR_QUAD_CurrentVersionRun_dfdf {
  strings:
    $key_dfdf = { 8c b0 [2] a8 be [2] 83 92 [2] ad b0 [2] b9 ab [2] b6 b1 [2] a8 ac [2] aa ad [2] b1 ab [2] ad ac [2] b1 83 }

  condition:
    any of them
}