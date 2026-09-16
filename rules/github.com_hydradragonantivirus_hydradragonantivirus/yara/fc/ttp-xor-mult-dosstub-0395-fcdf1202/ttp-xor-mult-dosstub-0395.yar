rule TTP_XOR_MULT_DOSStub_0395 {
  strings:
    $key_0395 = { 57 fd [2] 23 e5 [2] 64 e7 [2] 23 f6 [2] 6d fa [2] 61 f0 [2] 76 fb [2] 6d b5 [2] 50 }

  condition:
    any of them
}