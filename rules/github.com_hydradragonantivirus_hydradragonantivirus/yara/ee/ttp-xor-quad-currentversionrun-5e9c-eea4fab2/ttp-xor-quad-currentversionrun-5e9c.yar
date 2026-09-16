rule TTP_XOR_QUAD_CurrentVersionRun_5e9c {
  strings:
    $key_5e9c = { 0d f3 [2] 29 fd [2] 02 d1 [2] 2c f3 [2] 38 e8 [2] 37 f2 [2] 29 ef [2] 2b ee [2] 30 e8 [2] 2c ef [2] 30 c0 }

  condition:
    any of them
}