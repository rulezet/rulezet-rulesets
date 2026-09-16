rule TTP_XOR_QUAD_CurrentVersionRun_91c3 {
  strings:
    $key_91c3 = { c2 ac [2] e6 a2 [2] cd 8e [2] e3 ac [2] f7 b7 [2] f8 ad [2] e6 b0 [2] e4 b1 [2] ff b7 [2] e3 b0 [2] ff 9f }

  condition:
    any of them
}