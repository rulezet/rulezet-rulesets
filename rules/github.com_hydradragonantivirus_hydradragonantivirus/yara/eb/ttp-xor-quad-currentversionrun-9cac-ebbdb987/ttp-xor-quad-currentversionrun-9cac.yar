rule TTP_XOR_QUAD_CurrentVersionRun_9cac {
  strings:
    $key_9cac = { cf c3 [2] eb cd [2] c0 e1 [2] ee c3 [2] fa d8 [2] f5 c2 [2] eb df [2] e9 de [2] f2 d8 [2] ee df [2] f2 f0 }

  condition:
    any of them
}