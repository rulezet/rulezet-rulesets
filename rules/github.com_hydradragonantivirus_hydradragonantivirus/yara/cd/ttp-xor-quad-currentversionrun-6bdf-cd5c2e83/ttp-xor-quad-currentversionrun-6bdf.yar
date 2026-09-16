rule TTP_XOR_QUAD_CurrentVersionRun_6bdf {
  strings:
    $key_6bdf = { 38 b0 [2] 1c be [2] 37 92 [2] 19 b0 [2] 0d ab [2] 02 b1 [2] 1c ac [2] 1e ad [2] 05 ab [2] 19 ac [2] 05 83 }

  condition:
    any of them
}