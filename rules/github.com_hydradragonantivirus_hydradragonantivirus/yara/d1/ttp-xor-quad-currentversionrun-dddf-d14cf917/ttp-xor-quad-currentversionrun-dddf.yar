rule TTP_XOR_QUAD_CurrentVersionRun_dddf {
  strings:
    $key_dddf = { 8e b0 [2] aa be [2] 81 92 [2] af b0 [2] bb ab [2] b4 b1 [2] aa ac [2] a8 ad [2] b3 ab [2] af ac [2] b3 83 }

  condition:
    any of them
}