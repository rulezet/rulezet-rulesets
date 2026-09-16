rule TTP_XOR_QUAD_CurrentVersionRun_55df {
  strings:
    $key_55df = { 06 b0 [2] 22 be [2] 09 92 [2] 27 b0 [2] 33 ab [2] 3c b1 [2] 22 ac [2] 20 ad [2] 3b ab [2] 27 ac [2] 3b 83 }

  condition:
    any of them
}