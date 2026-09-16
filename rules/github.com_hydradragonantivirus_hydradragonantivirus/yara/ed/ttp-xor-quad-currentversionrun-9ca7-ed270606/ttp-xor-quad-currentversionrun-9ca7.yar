rule TTP_XOR_QUAD_CurrentVersionRun_9ca7 {
  strings:
    $key_9ca7 = { cf c8 [2] eb c6 [2] c0 ea [2] ee c8 [2] fa d3 [2] f5 c9 [2] eb d4 [2] e9 d5 [2] f2 d3 [2] ee d4 [2] f2 fb }

  condition:
    any of them
}