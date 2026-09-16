rule TTP_XOR_MULT_DOSStub_4289 {
  strings:
    $key_4289 = { 16 e1 [2] 62 f9 [2] 25 fb [2] 62 ea [2] 2c e6 [2] 20 ec [2] 37 e7 [2] 2c a9 [2] 11 }

  condition:
    any of them
}