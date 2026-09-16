rule TTP_XOR_MULT_DOSStub_0495 {
  strings:
    $key_0495 = { 50 fd [2] 24 e5 [2] 63 e7 [2] 24 f6 [2] 6a fa [2] 66 f0 [2] 71 fb [2] 6a b5 [2] 57 }

  condition:
    any of them
}