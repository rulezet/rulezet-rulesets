rule TTP_XOR_QUAD_CurrentVersionRun_9a8e {
  strings:
    $key_9a8e = { c9 e1 [2] ed ef [2] c6 c3 [2] e8 e1 [2] fc fa [2] f3 e0 [2] ed fd [2] ef fc [2] f4 fa [2] e8 fd [2] f4 d2 }

  condition:
    any of them
}