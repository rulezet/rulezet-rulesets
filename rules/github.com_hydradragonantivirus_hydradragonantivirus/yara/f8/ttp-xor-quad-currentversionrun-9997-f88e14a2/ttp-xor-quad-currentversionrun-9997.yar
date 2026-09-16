rule TTP_XOR_QUAD_CurrentVersionRun_9997 {
  strings:
    $key_9997 = { ca f8 [2] ee f6 [2] c5 da [2] eb f8 [2] ff e3 [2] f0 f9 [2] ee e4 [2] ec e5 [2] f7 e3 [2] eb e4 [2] f7 cb }

  condition:
    any of them
}