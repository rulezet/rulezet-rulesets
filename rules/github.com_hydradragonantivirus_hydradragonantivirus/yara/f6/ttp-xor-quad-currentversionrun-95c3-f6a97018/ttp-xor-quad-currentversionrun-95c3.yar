rule TTP_XOR_QUAD_CurrentVersionRun_95c3 {
  strings:
    $key_95c3 = { c6 ac [2] e2 a2 [2] c9 8e [2] e7 ac [2] f3 b7 [2] fc ad [2] e2 b0 [2] e0 b1 [2] fb b7 [2] e7 b0 [2] fb 9f }

  condition:
    any of them
}