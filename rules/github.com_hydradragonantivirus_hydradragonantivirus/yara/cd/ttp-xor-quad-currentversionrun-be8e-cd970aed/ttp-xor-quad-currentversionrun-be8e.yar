rule TTP_XOR_QUAD_CurrentVersionRun_be8e {
  strings:
    $key_be8e = { ed e1 [2] c9 ef [2] e2 c3 [2] cc e1 [2] d8 fa [2] d7 e0 [2] c9 fd [2] cb fc [2] d0 fa [2] cc fd [2] d0 d2 }

  condition:
    any of them
}