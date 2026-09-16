rule TTP_XOR_QUAD_CurrentVersionRun_5a8e {
  strings:
    $key_5a8e = { 09 e1 [2] 2d ef [2] 06 c3 [2] 28 e1 [2] 3c fa [2] 33 e0 [2] 2d fd [2] 2f fc [2] 34 fa [2] 28 fd [2] 34 d2 }

  condition:
    any of them
}