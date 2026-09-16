rule TTP_XOR_MULT_DOSStub_6998 {
  strings:
    $key_6998 = { 3d f0 [2] 49 e8 [2] 0e ea [2] 49 fb [2] 07 f7 [2] 0b fd [2] 1c f6 [2] 07 b8 [2] 3a }

  condition:
    any of them
}