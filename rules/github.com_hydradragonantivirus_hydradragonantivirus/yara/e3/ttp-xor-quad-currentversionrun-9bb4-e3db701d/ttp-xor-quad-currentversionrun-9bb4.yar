rule TTP_XOR_QUAD_CurrentVersionRun_9bb4 {
  strings:
    $key_9bb4 = { c8 db [2] ec d5 [2] c7 f9 [2] e9 db [2] fd c0 [2] f2 da [2] ec c7 [2] ee c6 [2] f5 c0 [2] e9 c7 [2] f5 e8 }

  condition:
    any of them
}