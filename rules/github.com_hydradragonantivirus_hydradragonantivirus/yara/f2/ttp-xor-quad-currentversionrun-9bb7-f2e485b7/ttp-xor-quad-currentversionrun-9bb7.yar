rule TTP_XOR_QUAD_CurrentVersionRun_9bb7 {
  strings:
    $key_9bb7 = { c8 d8 [2] ec d6 [2] c7 fa [2] e9 d8 [2] fd c3 [2] f2 d9 [2] ec c4 [2] ee c5 [2] f5 c3 [2] e9 c4 [2] f5 eb }

  condition:
    any of them
}