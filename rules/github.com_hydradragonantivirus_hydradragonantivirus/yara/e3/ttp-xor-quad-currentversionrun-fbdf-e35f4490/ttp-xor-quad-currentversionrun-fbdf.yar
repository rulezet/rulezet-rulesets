rule TTP_XOR_QUAD_CurrentVersionRun_fbdf {
  strings:
    $key_fbdf = { a8 b0 [2] 8c be [2] a7 92 [2] 89 b0 [2] 9d ab [2] 92 b1 [2] 8c ac [2] 8e ad [2] 95 ab [2] 89 ac [2] 95 83 }

  condition:
    any of them
}