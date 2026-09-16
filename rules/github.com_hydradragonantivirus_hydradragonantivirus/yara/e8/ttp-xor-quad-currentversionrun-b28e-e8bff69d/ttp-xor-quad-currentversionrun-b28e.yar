rule TTP_XOR_QUAD_CurrentVersionRun_b28e {
  strings:
    $key_b28e = { e1 e1 [2] c5 ef [2] ee c3 [2] c0 e1 [2] d4 fa [2] db e0 [2] c5 fd [2] c7 fc [2] dc fa [2] c0 fd [2] dc d2 }

  condition:
    any of them
}