rule TTP_XOR_QUAD_CurrentVersionRun_0b8e {
  strings:
    $key_0b8e = { 58 e1 [2] 7c ef [2] 57 c3 [2] 79 e1 [2] 6d fa [2] 62 e0 [2] 7c fd [2] 7e fc [2] 65 fa [2] 79 fd [2] 65 d2 }

  condition:
    any of them
}