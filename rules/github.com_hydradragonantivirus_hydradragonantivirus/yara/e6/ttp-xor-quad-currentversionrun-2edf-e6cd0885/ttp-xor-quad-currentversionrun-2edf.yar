rule TTP_XOR_QUAD_CurrentVersionRun_2edf {
  strings:
    $key_2edf = { 7d b0 [2] 59 be [2] 72 92 [2] 5c b0 [2] 48 ab [2] 47 b1 [2] 59 ac [2] 5b ad [2] 40 ab [2] 5c ac [2] 40 83 }

  condition:
    any of them
}