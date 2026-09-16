rule TTP_XOR_QUAD_CurrentVersionRun_9c86 {
  strings:
    $key_9c86 = { cf e9 [2] eb e7 [2] c0 cb [2] ee e9 [2] fa f2 [2] f5 e8 [2] eb f5 [2] e9 f4 [2] f2 f2 [2] ee f5 [2] f2 da }

  condition:
    any of them
}