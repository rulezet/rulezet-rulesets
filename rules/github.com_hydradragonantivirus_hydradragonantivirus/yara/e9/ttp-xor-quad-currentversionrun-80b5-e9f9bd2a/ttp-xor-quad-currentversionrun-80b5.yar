rule TTP_XOR_QUAD_CurrentVersionRun_80b5 {
  strings:
    $key_80b5 = { d3 da [2] f7 d4 [2] dc f8 [2] f2 da [2] e6 c1 [2] e9 db [2] f7 c6 [2] f5 c7 [2] ee c1 [2] f2 c6 [2] ee e9 }

  condition:
    any of them
}