rule TTP_XOR_QUAD_CurrentVersionRun_96c3 {
  strings:
    $key_96c3 = { c5 ac [2] e1 a2 [2] ca 8e [2] e4 ac [2] f0 b7 [2] ff ad [2] e1 b0 [2] e3 b1 [2] f8 b7 [2] e4 b0 [2] f8 9f }

  condition:
    any of them
}