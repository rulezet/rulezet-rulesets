rule TTP_XOR_QUAD_CurrentVersionRun_4bdf {
  strings:
    $key_4bdf = { 18 b0 [2] 3c be [2] 17 92 [2] 39 b0 [2] 2d ab [2] 22 b1 [2] 3c ac [2] 3e ad [2] 25 ab [2] 39 ac [2] 25 83 }

  condition:
    any of them
}