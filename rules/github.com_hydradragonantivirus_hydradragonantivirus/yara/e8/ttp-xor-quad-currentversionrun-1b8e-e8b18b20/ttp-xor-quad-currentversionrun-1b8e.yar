rule TTP_XOR_QUAD_CurrentVersionRun_1b8e {
  strings:
    $key_1b8e = { 48 e1 [2] 6c ef [2] 47 c3 [2] 69 e1 [2] 7d fa [2] 72 e0 [2] 6c fd [2] 6e fc [2] 75 fa [2] 69 fd [2] 75 d2 }

  condition:
    any of them
}