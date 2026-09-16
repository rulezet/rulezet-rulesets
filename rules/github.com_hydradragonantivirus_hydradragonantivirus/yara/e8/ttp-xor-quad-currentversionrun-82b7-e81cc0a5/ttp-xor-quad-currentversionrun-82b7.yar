rule TTP_XOR_QUAD_CurrentVersionRun_82b7 {
  strings:
    $key_82b7 = { d1 d8 [2] f5 d6 [2] de fa [2] f0 d8 [2] e4 c3 [2] eb d9 [2] f5 c4 [2] f7 c5 [2] ec c3 [2] f0 c4 [2] ec eb }

  condition:
    any of them
}