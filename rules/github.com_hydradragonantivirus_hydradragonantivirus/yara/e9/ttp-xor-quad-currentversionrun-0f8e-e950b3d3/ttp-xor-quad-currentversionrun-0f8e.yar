rule TTP_XOR_QUAD_CurrentVersionRun_0f8e {
  strings:
    $key_0f8e = { 5c e1 [2] 78 ef [2] 53 c3 [2] 7d e1 [2] 69 fa [2] 66 e0 [2] 78 fd [2] 7a fc [2] 61 fa [2] 7d fd [2] 61 d2 }

  condition:
    any of them
}