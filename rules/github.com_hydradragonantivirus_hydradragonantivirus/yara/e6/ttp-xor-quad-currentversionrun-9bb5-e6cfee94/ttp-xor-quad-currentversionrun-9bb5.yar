rule TTP_XOR_QUAD_CurrentVersionRun_9bb5 {
  strings:
    $key_9bb5 = { c8 da [2] ec d4 [2] c7 f8 [2] e9 da [2] fd c1 [2] f2 db [2] ec c6 [2] ee c7 [2] f5 c1 [2] e9 c6 [2] f5 e9 }

  condition:
    any of them
}