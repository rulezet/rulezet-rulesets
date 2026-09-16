rule TTP_XOR_QUAD_CurrentVersionRun_82bb {
  strings:
    $key_82bb = { d1 d4 [2] f5 da [2] de f6 [2] f0 d4 [2] e4 cf [2] eb d5 [2] f5 c8 [2] f7 c9 [2] ec cf [2] f0 c8 [2] ec e7 }

  condition:
    any of them
}