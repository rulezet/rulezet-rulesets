rule TTP_XOR_QUAD_CurrentVersionRun_81d3 {
  strings:
    $key_81d3 = { d2 bc [2] f6 b2 [2] dd 9e [2] f3 bc [2] e7 a7 [2] e8 bd [2] f6 a0 [2] f4 a1 [2] ef a7 [2] f3 a0 [2] ef 8f }

  condition:
    any of them
}