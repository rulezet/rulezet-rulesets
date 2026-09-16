rule TTP_XOR_MULT_DOSStub_5998 {
  strings:
    $key_5998 = { 0d f0 [2] 79 e8 [2] 3e ea [2] 79 fb [2] 37 f7 [2] 3b fd [2] 2c f6 [2] 37 b8 [2] 0a }

  condition:
    any of them
}