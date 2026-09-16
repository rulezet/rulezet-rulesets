rule TTP_XOR_QUAD_CurrentVersionRun_f48e {
  strings:
    $key_f48e = { a7 e1 [2] 83 ef [2] a8 c3 [2] 86 e1 [2] 92 fa [2] 9d e0 [2] 83 fd [2] 81 fc [2] 9a fa [2] 86 fd [2] 9a d2 }

  condition:
    any of them
}