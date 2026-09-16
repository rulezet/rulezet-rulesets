rule TTP_XOR_MULT_DOSStub_4693 {
  strings:
    $key_4693 = { 12 fb [2] 66 e3 [2] 21 e1 [2] 66 f0 [2] 28 fc [2] 24 f6 [2] 33 fd [2] 28 b3 [2] 15 }

  condition:
    any of them
}