rule TTP_XOR_QUAD_CurrentVersionRun_9a89 {
  strings:
    $key_9a89 = { c9 e6 [2] ed e8 [2] c6 c4 [2] e8 e6 [2] fc fd [2] f3 e7 [2] ed fa [2] ef fb [2] f4 fd [2] e8 fa [2] f4 d5 }

  condition:
    any of them
}