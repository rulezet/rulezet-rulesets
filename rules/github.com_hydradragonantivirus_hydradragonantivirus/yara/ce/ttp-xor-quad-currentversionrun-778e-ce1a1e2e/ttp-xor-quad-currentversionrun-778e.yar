rule TTP_XOR_QUAD_CurrentVersionRun_778e {
  strings:
    $key_778e = { 24 e1 [2] 00 ef [2] 2b c3 [2] 05 e1 [2] 11 fa [2] 1e e0 [2] 00 fd [2] 02 fc [2] 19 fa [2] 05 fd [2] 19 d2 }

  condition:
    any of them
}