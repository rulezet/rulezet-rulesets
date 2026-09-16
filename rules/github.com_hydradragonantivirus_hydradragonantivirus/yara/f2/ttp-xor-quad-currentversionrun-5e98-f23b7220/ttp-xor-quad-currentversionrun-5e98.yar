rule TTP_XOR_QUAD_CurrentVersionRun_5e98 {
  strings:
    $key_5e98 = { 0d f7 [2] 29 f9 [2] 02 d5 [2] 2c f7 [2] 38 ec [2] 37 f6 [2] 29 eb [2] 2b ea [2] 30 ec [2] 2c eb [2] 30 c4 }

  condition:
    any of them
}