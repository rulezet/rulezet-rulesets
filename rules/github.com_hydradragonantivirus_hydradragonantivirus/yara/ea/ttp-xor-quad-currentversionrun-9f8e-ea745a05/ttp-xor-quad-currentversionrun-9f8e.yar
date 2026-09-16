rule TTP_XOR_QUAD_CurrentVersionRun_9f8e {
  strings:
    $key_9f8e = { cc e1 [2] e8 ef [2] c3 c3 [2] ed e1 [2] f9 fa [2] f6 e0 [2] e8 fd [2] ea fc [2] f1 fa [2] ed fd [2] f1 d2 }

  condition:
    any of them
}