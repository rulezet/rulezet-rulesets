rule TTP_XOR_QUAD_CurrentVersionRun_9cb2 {
  strings:
    $key_9cb2 = { cf dd [2] eb d3 [2] c0 ff [2] ee dd [2] fa c6 [2] f5 dc [2] eb c1 [2] e9 c0 [2] f2 c6 [2] ee c1 [2] f2 ee }

  condition:
    any of them
}