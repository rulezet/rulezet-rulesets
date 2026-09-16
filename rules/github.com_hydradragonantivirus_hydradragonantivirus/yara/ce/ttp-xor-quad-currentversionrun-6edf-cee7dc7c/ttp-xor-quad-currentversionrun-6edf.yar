rule TTP_XOR_QUAD_CurrentVersionRun_6edf {
  strings:
    $key_6edf = { 3d b0 [2] 19 be [2] 32 92 [2] 1c b0 [2] 08 ab [2] 07 b1 [2] 19 ac [2] 1b ad [2] 00 ab [2] 1c ac [2] 00 83 }

  condition:
    any of them
}