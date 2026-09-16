rule TTP_XOR_QUAD_CurrentVersionRun_9c81 {
  strings:
    $key_9c81 = { cf ee [2] eb e0 [2] c0 cc [2] ee ee [2] fa f5 [2] f5 ef [2] eb f2 [2] e9 f3 [2] f2 f5 [2] ee f2 [2] f2 dd }

  condition:
    any of them
}