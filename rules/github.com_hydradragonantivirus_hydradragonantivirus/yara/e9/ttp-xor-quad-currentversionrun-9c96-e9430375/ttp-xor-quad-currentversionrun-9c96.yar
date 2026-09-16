rule TTP_XOR_QUAD_CurrentVersionRun_9c96 {
  strings:
    $key_9c96 = { cf f9 [2] eb f7 [2] c0 db [2] ee f9 [2] fa e2 [2] f5 f8 [2] eb e5 [2] e9 e4 [2] f2 e2 [2] ee e5 [2] f2 ca }

  condition:
    any of them
}