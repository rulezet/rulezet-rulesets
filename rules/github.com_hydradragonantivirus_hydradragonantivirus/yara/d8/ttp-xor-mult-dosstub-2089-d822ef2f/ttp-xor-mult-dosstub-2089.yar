rule TTP_XOR_MULT_DOSStub_2089 {
  strings:
    $key_2089 = { 74 e1 [2] 00 f9 [2] 47 fb [2] 00 ea [2] 4e e6 [2] 42 ec [2] 55 e7 [2] 4e a9 [2] 73 }

  condition:
    any of them
}