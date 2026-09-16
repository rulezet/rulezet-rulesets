rule TTP_XOR_MULT_DOSStub_8d89 {
  strings:
    $key_8d89 = { d9 e1 [2] ad f9 [2] ea fb [2] ad ea [2] e3 e6 [2] ef ec [2] f8 e7 [2] e3 a9 [2] de }

  condition:
    any of them
}