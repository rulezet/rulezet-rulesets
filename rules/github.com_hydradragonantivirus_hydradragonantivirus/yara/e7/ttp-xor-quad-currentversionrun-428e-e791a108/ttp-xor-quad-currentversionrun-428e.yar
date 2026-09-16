rule TTP_XOR_QUAD_CurrentVersionRun_428e {
  strings:
    $key_428e = { 11 e1 [2] 35 ef [2] 1e c3 [2] 30 e1 [2] 24 fa [2] 2b e0 [2] 35 fd [2] 37 fc [2] 2c fa [2] 30 fd [2] 2c d2 }

  condition:
    any of them
}