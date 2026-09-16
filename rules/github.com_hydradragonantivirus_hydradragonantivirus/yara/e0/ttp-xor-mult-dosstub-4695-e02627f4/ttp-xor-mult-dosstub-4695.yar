rule TTP_XOR_MULT_DOSStub_4695 {
  strings:
    $key_4695 = { 12 fd [2] 66 e5 [2] 21 e7 [2] 66 f6 [2] 28 fa [2] 24 f0 [2] 33 fb [2] 28 b5 [2] 15 }

  condition:
    any of them
}