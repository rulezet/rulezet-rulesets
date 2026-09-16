rule TTP_XOR_QUAD_CurrentVersionRun_92c3 {
  strings:
    $key_92c3 = { c1 ac [2] e5 a2 [2] ce 8e [2] e0 ac [2] f4 b7 [2] fb ad [2] e5 b0 [2] e7 b1 [2] fc b7 [2] e0 b0 [2] fc 9f }

  condition:
    any of them
}