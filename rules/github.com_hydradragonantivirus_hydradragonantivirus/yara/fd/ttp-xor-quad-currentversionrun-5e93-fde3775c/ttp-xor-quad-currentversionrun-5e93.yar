rule TTP_XOR_QUAD_CurrentVersionRun_5e93 {
  strings:
    $key_5e93 = { 0d fc [2] 29 f2 [2] 02 de [2] 2c fc [2] 38 e7 [2] 37 fd [2] 29 e0 [2] 2b e1 [2] 30 e7 [2] 2c e0 [2] 30 cf }

  condition:
    any of them
}