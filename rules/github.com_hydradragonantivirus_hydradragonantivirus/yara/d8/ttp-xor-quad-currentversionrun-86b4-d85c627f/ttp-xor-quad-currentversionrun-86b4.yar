rule TTP_XOR_QUAD_CurrentVersionRun_86b4 {
  strings:
    $key_86b4 = { d5 db [2] f1 d5 [2] da f9 [2] f4 db [2] e0 c0 [2] ef da [2] f1 c7 [2] f3 c6 [2] e8 c0 [2] f4 c7 [2] e8 e8 }

  condition:
    any of them
}