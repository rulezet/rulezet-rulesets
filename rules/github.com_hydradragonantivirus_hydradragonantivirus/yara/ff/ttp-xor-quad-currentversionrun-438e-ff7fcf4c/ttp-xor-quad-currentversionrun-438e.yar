rule TTP_XOR_QUAD_CurrentVersionRun_438e {
  strings:
    $key_438e = { 10 e1 [2] 34 ef [2] 1f c3 [2] 31 e1 [2] 25 fa [2] 2a e0 [2] 34 fd [2] 36 fc [2] 2d fa [2] 31 fd [2] 2d d2 }

  condition:
    any of them
}