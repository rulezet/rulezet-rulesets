rule TTP_XOR_QUAD_CurrentVersionRun_9ac3 {
  strings:
    $key_9ac3 = { c9 ac [2] ed a2 [2] c6 8e [2] e8 ac [2] fc b7 [2] f3 ad [2] ed b0 [2] ef b1 [2] f4 b7 [2] e8 b0 [2] f4 9f }

  condition:
    any of them
}