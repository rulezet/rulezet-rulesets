rule TTP_XOR_QUAD_CurrentVersionRun_008e {
  strings:
    $key_008e = { 53 e1 [2] 77 ef [2] 5c c3 [2] 72 e1 [2] 66 fa [2] 69 e0 [2] 77 fd [2] 75 fc [2] 6e fa [2] 72 fd [2] 6e d2 }

  condition:
    any of them
}