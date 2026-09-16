rule TTP_XOR_QUAD_CurrentVersionRun_7f8e {
  strings:
    $key_7f8e = { 2c e1 [2] 08 ef [2] 23 c3 [2] 0d e1 [2] 19 fa [2] 16 e0 [2] 08 fd [2] 0a fc [2] 11 fa [2] 0d fd [2] 11 d2 }

  condition:
    any of them
}