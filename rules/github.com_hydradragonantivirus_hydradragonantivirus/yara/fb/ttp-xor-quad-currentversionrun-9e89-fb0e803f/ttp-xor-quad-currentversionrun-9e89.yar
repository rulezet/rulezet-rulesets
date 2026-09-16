rule TTP_XOR_QUAD_CurrentVersionRun_9e89 {
  strings:
    $key_9e89 = { cd e6 [2] e9 e8 [2] c2 c4 [2] ec e6 [2] f8 fd [2] f7 e7 [2] e9 fa [2] eb fb [2] f0 fd [2] ec fa [2] f0 d5 }

  condition:
    any of them
}