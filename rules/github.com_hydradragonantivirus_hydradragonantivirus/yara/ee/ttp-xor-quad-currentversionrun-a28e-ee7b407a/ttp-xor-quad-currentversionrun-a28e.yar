rule TTP_XOR_QUAD_CurrentVersionRun_a28e {
  strings:
    $key_a28e = { f1 e1 [2] d5 ef [2] fe c3 [2] d0 e1 [2] c4 fa [2] cb e0 [2] d5 fd [2] d7 fc [2] cc fa [2] d0 fd [2] cc d2 }

  condition:
    any of them
}