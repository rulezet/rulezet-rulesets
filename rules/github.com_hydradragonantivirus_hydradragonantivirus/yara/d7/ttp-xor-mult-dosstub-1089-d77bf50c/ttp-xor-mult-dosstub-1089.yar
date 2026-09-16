rule TTP_XOR_MULT_DOSStub_1089 {
  strings:
    $key_1089 = { 44 e1 [2] 30 f9 [2] 77 fb [2] 30 ea [2] 7e e6 [2] 72 ec [2] 65 e7 [2] 7e a9 [2] 43 }

  condition:
    any of them
}