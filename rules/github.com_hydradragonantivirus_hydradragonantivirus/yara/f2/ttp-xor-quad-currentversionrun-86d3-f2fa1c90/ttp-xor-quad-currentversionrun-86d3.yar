rule TTP_XOR_QUAD_CurrentVersionRun_86d3 {
  strings:
    $key_86d3 = { d5 bc [2] f1 b2 [2] da 9e [2] f4 bc [2] e0 a7 [2] ef bd [2] f1 a0 [2] f3 a1 [2] e8 a7 [2] f4 a0 [2] e8 8f }

  condition:
    any of them
}