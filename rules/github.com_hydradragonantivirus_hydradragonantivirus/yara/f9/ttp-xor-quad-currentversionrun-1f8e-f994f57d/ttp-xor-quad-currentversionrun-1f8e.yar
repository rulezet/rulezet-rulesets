rule TTP_XOR_QUAD_CurrentVersionRun_1f8e {
  strings:
    $key_1f8e = { 4c e1 [2] 68 ef [2] 43 c3 [2] 6d e1 [2] 79 fa [2] 76 e0 [2] 68 fd [2] 6a fc [2] 71 fa [2] 6d fd [2] 71 d2 }

  condition:
    any of them
}