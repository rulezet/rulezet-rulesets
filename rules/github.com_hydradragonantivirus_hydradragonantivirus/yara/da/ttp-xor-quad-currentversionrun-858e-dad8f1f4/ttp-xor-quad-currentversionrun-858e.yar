rule TTP_XOR_QUAD_CurrentVersionRun_858e {
  strings:
    $key_858e = { d6 e1 [2] f2 ef [2] d9 c3 [2] f7 e1 [2] e3 fa [2] ec e0 [2] f2 fd [2] f0 fc [2] eb fa [2] f7 fd [2] eb d2 }

  condition:
    any of them
}