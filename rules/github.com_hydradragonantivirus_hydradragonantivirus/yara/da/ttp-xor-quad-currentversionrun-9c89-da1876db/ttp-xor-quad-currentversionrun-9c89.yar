rule TTP_XOR_QUAD_CurrentVersionRun_9c89 {
  strings:
    $key_9c89 = { cf e6 [2] eb e8 [2] c0 c4 [2] ee e6 [2] fa fd [2] f5 e7 [2] eb fa [2] e9 fb [2] f2 fd [2] ee fa [2] f2 d5 }

  condition:
    any of them
}