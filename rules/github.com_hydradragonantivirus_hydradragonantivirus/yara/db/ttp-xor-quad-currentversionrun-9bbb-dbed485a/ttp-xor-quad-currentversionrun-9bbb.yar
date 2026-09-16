rule TTP_XOR_QUAD_CurrentVersionRun_9bbb {
  strings:
    $key_9bbb = { c8 d4 [2] ec da [2] c7 f6 [2] e9 d4 [2] fd cf [2] f2 d5 [2] ec c8 [2] ee c9 [2] f5 cf [2] e9 c8 [2] f5 e7 }

  condition:
    any of them
}