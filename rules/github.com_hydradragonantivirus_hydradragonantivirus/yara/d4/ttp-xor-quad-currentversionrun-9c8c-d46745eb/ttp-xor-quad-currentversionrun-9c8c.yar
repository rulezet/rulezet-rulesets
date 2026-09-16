rule TTP_XOR_QUAD_CurrentVersionRun_9c8c {
  strings:
    $key_9c8c = { cf e3 [2] eb ed [2] c0 c1 [2] ee e3 [2] fa f8 [2] f5 e2 [2] eb ff [2] e9 fe [2] f2 f8 [2] ee ff [2] f2 d0 }

  condition:
    any of them
}