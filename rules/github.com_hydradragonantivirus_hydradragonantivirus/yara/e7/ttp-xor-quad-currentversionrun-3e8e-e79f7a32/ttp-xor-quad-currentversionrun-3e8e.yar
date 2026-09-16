rule TTP_XOR_QUAD_CurrentVersionRun_3e8e {
  strings:
    $key_3e8e = { 6d e1 [2] 49 ef [2] 62 c3 [2] 4c e1 [2] 58 fa [2] 57 e0 [2] 49 fd [2] 4b fc [2] 50 fa [2] 4c fd [2] 50 d2 }

  condition:
    any of them
}