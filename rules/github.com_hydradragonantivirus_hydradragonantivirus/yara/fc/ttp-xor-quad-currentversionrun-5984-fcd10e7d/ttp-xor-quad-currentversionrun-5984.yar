rule TTP_XOR_QUAD_CurrentVersionRun_5984 {
  strings:
    $key_5984 = { 0a eb [2] 2e e5 [2] 05 c9 [2] 2b eb [2] 3f f0 [2] 30 ea [2] 2e f7 [2] 2c f6 [2] 37 f0 [2] 2b f7 [2] 37 d8 }

  condition:
    any of them
}