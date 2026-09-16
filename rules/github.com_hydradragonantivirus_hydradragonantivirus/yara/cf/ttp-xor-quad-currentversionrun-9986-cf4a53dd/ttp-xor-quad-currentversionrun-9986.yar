rule TTP_XOR_QUAD_CurrentVersionRun_9986 {
  strings:
    $key_9986 = { ca e9 [2] ee e7 [2] c5 cb [2] eb e9 [2] ff f2 [2] f0 e8 [2] ee f5 [2] ec f4 [2] f7 f2 [2] eb f5 [2] f7 da }

  condition:
    any of them
}