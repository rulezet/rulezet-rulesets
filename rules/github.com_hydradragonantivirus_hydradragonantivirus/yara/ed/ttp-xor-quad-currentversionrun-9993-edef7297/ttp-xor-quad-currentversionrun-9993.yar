rule TTP_XOR_QUAD_CurrentVersionRun_9993 {
  strings:
    $key_9993 = { ca fc [2] ee f2 [2] c5 de [2] eb fc [2] ff e7 [2] f0 fd [2] ee e0 [2] ec e1 [2] f7 e7 [2] eb e0 [2] f7 cf }

  condition:
    any of them
}