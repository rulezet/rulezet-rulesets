rule TTP_XOR_MULT_DOSStub_5495 {
  strings:
    $key_5495 = { 00 fd [2] 74 e5 [2] 33 e7 [2] 74 f6 [2] 3a fa [2] 36 f0 [2] 21 fb [2] 3a b5 [2] 07 }

  condition:
    any of them
}