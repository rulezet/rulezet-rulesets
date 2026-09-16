rule TTP_XOR_QUAD_CurrentVersionRun_398e {
  strings:
    $key_398e = { 6a e1 [2] 4e ef [2] 65 c3 [2] 4b e1 [2] 5f fa [2] 50 e0 [2] 4e fd [2] 4c fc [2] 57 fa [2] 4b fd [2] 57 d2 }

  condition:
    any of them
}