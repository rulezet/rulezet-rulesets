rule TTP_XOR_MULT_DOSStub_7593 {
  strings:
    $key_7593 = { 21 fb [2] 55 e3 [2] 12 e1 [2] 55 f0 [2] 1b fc [2] 17 f6 [2] 00 fd [2] 1b b3 [2] 26 }

  condition:
    any of them
}