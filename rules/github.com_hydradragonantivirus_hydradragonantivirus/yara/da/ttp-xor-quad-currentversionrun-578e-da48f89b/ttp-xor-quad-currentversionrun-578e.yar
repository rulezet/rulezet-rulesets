rule TTP_XOR_QUAD_CurrentVersionRun_578e {
  strings:
    $key_578e = { 04 e1 [2] 20 ef [2] 0b c3 [2] 25 e1 [2] 31 fa [2] 3e e0 [2] 20 fd [2] 22 fc [2] 39 fa [2] 25 fd [2] 39 d2 }

  condition:
    any of them
}