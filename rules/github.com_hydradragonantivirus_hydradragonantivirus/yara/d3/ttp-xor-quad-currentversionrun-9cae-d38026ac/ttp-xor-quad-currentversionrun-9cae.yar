rule TTP_XOR_QUAD_CurrentVersionRun_9cae {
  strings:
    $key_9cae = { cf c1 [2] eb cf [2] c0 e3 [2] ee c1 [2] fa da [2] f5 c0 [2] eb dd [2] e9 dc [2] f2 da [2] ee dd [2] f2 f2 }

  condition:
    any of them
}