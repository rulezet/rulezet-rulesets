rule TTP_XOR_QUAD_CurrentVersionRun_9e95 {
  strings:
    $key_9e95 = { cd fa [2] e9 f4 [2] c2 d8 [2] ec fa [2] f8 e1 [2] f7 fb [2] e9 e6 [2] eb e7 [2] f0 e1 [2] ec e6 [2] f0 c9 }

  condition:
    any of them
}