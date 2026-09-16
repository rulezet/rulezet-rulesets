rule TTP_XOR_QUAD_CurrentVersionRun_4a8e {
  strings:
    $key_4a8e = { 19 e1 [2] 3d ef [2] 16 c3 [2] 38 e1 [2] 2c fa [2] 23 e0 [2] 3d fd [2] 3f fc [2] 24 fa [2] 38 fd [2] 24 d2 }

  condition:
    any of them
}