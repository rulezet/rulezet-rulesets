rule TTP_XOR_MULT_DOSStub_4089 {
  strings:
    $key_4089 = { 14 e1 [2] 60 f9 [2] 27 fb [2] 60 ea [2] 2e e6 [2] 22 ec [2] 35 e7 [2] 2e a9 [2] 13 }

  condition:
    any of them
}