rule TTP_XOR_QUAD_CurrentVersionRun_d08e {
  strings:
    $key_d08e = { 83 e1 [2] a7 ef [2] 8c c3 [2] a2 e1 [2] b6 fa [2] b9 e0 [2] a7 fd [2] a5 fc [2] be fa [2] a2 fd [2] be d2 }

  condition:
    any of them
}