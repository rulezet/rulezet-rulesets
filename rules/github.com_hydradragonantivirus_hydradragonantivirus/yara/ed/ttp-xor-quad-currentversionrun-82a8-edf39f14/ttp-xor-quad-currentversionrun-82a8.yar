rule TTP_XOR_QUAD_CurrentVersionRun_82a8 {
  strings:
    $key_82a8 = { d1 c7 [2] f5 c9 [2] de e5 [2] f0 c7 [2] e4 dc [2] eb c6 [2] f5 db [2] f7 da [2] ec dc [2] f0 db [2] ec f4 }

  condition:
    any of them
}