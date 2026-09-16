rule TTP_XOR_QUAD_CurrentVersionRun_2fdf {
  strings:
    $key_2fdf = { 7c b0 [2] 58 be [2] 73 92 [2] 5d b0 [2] 49 ab [2] 46 b1 [2] 58 ac [2] 5a ad [2] 41 ab [2] 5d ac [2] 41 83 }

  condition:
    any of them
}