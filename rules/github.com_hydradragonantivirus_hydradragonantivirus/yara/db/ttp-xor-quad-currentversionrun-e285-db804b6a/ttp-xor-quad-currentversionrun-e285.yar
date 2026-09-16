rule TTP_XOR_QUAD_CurrentVersionRun_e285 {
  strings:
    $key_e285 = { b1 ea [2] 95 e4 [2] be c8 [2] 90 ea [2] 84 f1 [2] 8b eb [2] 95 f6 [2] 97 f7 [2] 8c f1 [2] 90 f6 [2] 8c d9 }

  condition:
    any of them
}