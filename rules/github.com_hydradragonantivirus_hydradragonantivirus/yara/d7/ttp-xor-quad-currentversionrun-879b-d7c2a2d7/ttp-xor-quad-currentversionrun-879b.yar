rule TTP_XOR_QUAD_CurrentVersionRun_879b {
  strings:
    $key_879b = { d4 f4 [2] f0 fa [2] db d6 [2] f5 f4 [2] e1 ef [2] ee f5 [2] f0 e8 [2] f2 e9 [2] e9 ef [2] f5 e8 [2] e9 c7 }

  condition:
    any of them
}