rule TTP_XOR_QUAD_CurrentVersionRun_f4df {
  strings:
    $key_f4df = { a7 b0 [2] 83 be [2] a8 92 [2] 86 b0 [2] 92 ab [2] 9d b1 [2] 83 ac [2] 81 ad [2] 9a ab [2] 86 ac [2] 9a 83 }

  condition:
    any of them
}