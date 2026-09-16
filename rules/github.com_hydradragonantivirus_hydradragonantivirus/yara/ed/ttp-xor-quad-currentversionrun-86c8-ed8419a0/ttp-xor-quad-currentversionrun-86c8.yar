rule TTP_XOR_QUAD_CurrentVersionRun_86c8 {
  strings:
    $key_86c8 = { d5 a7 [2] f1 a9 [2] da 85 [2] f4 a7 [2] e0 bc [2] ef a6 [2] f1 bb [2] f3 ba [2] e8 bc [2] f4 bb [2] e8 94 }

  condition:
    any of them
}