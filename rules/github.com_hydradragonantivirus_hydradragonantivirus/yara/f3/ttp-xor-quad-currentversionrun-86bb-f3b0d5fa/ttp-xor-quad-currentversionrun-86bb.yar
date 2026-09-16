rule TTP_XOR_QUAD_CurrentVersionRun_86bb {
  strings:
    $key_86bb = { d5 d4 [2] f1 da [2] da f6 [2] f4 d4 [2] e0 cf [2] ef d5 [2] f1 c8 [2] f3 c9 [2] e8 cf [2] f4 c8 [2] e8 e7 }

  condition:
    any of them
}