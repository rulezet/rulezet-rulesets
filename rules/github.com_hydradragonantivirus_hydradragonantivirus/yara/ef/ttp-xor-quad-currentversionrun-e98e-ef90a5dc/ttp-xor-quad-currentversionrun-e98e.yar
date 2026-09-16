rule TTP_XOR_QUAD_CurrentVersionRun_e98e {
  strings:
    $key_e98e = { ba e1 [2] 9e ef [2] b5 c3 [2] 9b e1 [2] 8f fa [2] 80 e0 [2] 9e fd [2] 9c fc [2] 87 fa [2] 9b fd [2] 87 d2 }

  condition:
    any of them
}