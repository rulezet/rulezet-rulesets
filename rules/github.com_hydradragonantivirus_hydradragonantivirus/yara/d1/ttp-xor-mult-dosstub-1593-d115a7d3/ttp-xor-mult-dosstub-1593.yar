rule TTP_XOR_MULT_DOSStub_1593 {
  strings:
    $key_1593 = { 41 fb [2] 35 e3 [2] 72 e1 [2] 35 f0 [2] 7b fc [2] 77 f6 [2] 60 fd [2] 7b b3 [2] 46 }

  condition:
    any of them
}