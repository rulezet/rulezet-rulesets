rule TTP_XOR_QUAD_CurrentVersionRun_648e {
  strings:
    $key_648e = { 37 e1 [2] 13 ef [2] 38 c3 [2] 16 e1 [2] 02 fa [2] 0d e0 [2] 13 fd [2] 11 fc [2] 0a fa [2] 16 fd [2] 0a d2 }

  condition:
    any of them
}