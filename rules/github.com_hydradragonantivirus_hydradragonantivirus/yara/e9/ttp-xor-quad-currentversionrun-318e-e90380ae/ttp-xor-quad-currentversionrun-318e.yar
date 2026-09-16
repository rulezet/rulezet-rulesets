rule TTP_XOR_QUAD_CurrentVersionRun_318e {
  strings:
    $key_318e = { 62 e1 [2] 46 ef [2] 6d c3 [2] 43 e1 [2] 57 fa [2] 58 e0 [2] 46 fd [2] 44 fc [2] 5f fa [2] 43 fd [2] 5f d2 }

  condition:
    any of them
}