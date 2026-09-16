rule TTP_XOR_QUAD_CurrentVersionRun_3a8e {
  strings:
    $key_3a8e = { 69 e1 [2] 4d ef [2] 66 c3 [2] 48 e1 [2] 5c fa [2] 53 e0 [2] 4d fd [2] 4f fc [2] 54 fa [2] 48 fd [2] 54 d2 }

  condition:
    any of them
}