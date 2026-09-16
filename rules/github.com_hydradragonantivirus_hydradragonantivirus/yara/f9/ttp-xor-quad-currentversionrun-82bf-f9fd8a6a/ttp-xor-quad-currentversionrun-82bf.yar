rule TTP_XOR_QUAD_CurrentVersionRun_82bf {
  strings:
    $key_82bf = { d1 d0 [2] f5 de [2] de f2 [2] f0 d0 [2] e4 cb [2] eb d1 [2] f5 cc [2] f7 cd [2] ec cb [2] f0 cc [2] ec e3 }

  condition:
    any of them
}