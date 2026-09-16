rule TTP_XOR_QUAD_CurrentVersionRun_41c3 {
  strings:
    $key_41c3 = { 12 ac [2] 36 a2 [2] 1d 8e [2] 33 ac [2] 27 b7 [2] 28 ad [2] 36 b0 [2] 34 b1 [2] 2f b7 [2] 33 b0 [2] 2f 9f }

  condition:
    any of them
}