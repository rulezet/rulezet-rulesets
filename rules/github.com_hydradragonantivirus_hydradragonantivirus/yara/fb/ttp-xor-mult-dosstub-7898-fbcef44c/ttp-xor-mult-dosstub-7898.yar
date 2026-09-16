rule TTP_XOR_MULT_DOSStub_7898 {
  strings:
    $key_7898 = { 2c f0 [2] 58 e8 [2] 1f ea [2] 58 fb [2] 16 f7 [2] 1a fd [2] 0d f6 [2] 16 b8 [2] 2b }

  condition:
    any of them
}