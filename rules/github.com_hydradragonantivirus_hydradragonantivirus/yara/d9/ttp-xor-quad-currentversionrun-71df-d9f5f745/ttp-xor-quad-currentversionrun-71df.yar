rule TTP_XOR_QUAD_CurrentVersionRun_71df {
  strings:
    $key_71df = { 22 b0 [2] 06 be [2] 2d 92 [2] 03 b0 [2] 17 ab [2] 18 b1 [2] 06 ac [2] 04 ad [2] 1f ab [2] 03 ac [2] 1f 83 }

  condition:
    any of them
}