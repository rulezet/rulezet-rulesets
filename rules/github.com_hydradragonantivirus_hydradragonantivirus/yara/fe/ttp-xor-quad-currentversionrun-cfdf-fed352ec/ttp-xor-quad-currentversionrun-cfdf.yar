rule TTP_XOR_QUAD_CurrentVersionRun_cfdf {
  strings:
    $key_cfdf = { 9c b0 [2] b8 be [2] 93 92 [2] bd b0 [2] a9 ab [2] a6 b1 [2] b8 ac [2] ba ad [2] a1 ab [2] bd ac [2] a1 83 }

  condition:
    any of them
}