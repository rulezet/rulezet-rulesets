rule TTP_XOR_QUAD_CurrentVersionRun_6bc3 {
  strings:
    $key_6bc3 = { 38 ac [2] 1c a2 [2] 37 8e [2] 19 ac [2] 0d b7 [2] 02 ad [2] 1c b0 [2] 1e b1 [2] 05 b7 [2] 19 b0 [2] 05 9f }

  condition:
    any of them
}