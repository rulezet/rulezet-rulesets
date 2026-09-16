rule TTP_XOR_QUAD_CurrentVersionRun_278e {
  strings:
    $key_278e = { 74 e1 [2] 50 ef [2] 7b c3 [2] 55 e1 [2] 41 fa [2] 4e e0 [2] 50 fd [2] 52 fc [2] 49 fa [2] 55 fd [2] 49 d2 }

  condition:
    any of them
}