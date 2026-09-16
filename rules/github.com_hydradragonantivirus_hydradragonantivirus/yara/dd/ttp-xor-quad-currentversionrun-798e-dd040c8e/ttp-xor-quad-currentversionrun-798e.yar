rule TTP_XOR_QUAD_CurrentVersionRun_798e {
  strings:
    $key_798e = { 2a e1 [2] 0e ef [2] 25 c3 [2] 0b e1 [2] 1f fa [2] 10 e0 [2] 0e fd [2] 0c fc [2] 17 fa [2] 0b fd [2] 17 d2 }

  condition:
    any of them
}