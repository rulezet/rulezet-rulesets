rule TTP_XOR_QUAD_CurrentVersionRun_9c9a {
  strings:
    $key_9c9a = { cf f5 [2] eb fb [2] c0 d7 [2] ee f5 [2] fa ee [2] f5 f4 [2] eb e9 [2] e9 e8 [2] f2 ee [2] ee e9 [2] f2 c6 }

  condition:
    any of them
}