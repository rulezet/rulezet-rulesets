rule TTP_XOR_QUAD_CurrentVersionRun_508e {
  strings:
    $key_508e = { 03 e1 [2] 27 ef [2] 0c c3 [2] 22 e1 [2] 36 fa [2] 39 e0 [2] 27 fd [2] 25 fc [2] 3e fa [2] 22 fd [2] 3e d2 }

  condition:
    any of them
}