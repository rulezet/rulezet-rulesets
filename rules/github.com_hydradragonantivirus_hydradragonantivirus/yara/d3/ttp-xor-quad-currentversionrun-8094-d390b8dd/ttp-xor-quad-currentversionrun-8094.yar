rule TTP_XOR_QUAD_CurrentVersionRun_8094 {
  strings:
    $key_8094 = { d3 fb [2] f7 f5 [2] dc d9 [2] f2 fb [2] e6 e0 [2] e9 fa [2] f7 e7 [2] f5 e6 [2] ee e0 [2] f2 e7 [2] ee c8 }

  condition:
    any of them
}