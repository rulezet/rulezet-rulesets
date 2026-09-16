rule TTP_XOR_QUAD_CurrentVersionRun_96d3 {
  strings:
    $key_96d3 = { c5 bc [2] e1 b2 [2] ca 9e [2] e4 bc [2] f0 a7 [2] ff bd [2] e1 a0 [2] e3 a1 [2] f8 a7 [2] e4 a0 [2] f8 8f }

  condition:
    any of them
}