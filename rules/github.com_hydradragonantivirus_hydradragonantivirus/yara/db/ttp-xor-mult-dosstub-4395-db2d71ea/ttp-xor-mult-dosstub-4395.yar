rule TTP_XOR_MULT_DOSStub_4395 {
  strings:
    $key_4395 = { 17 fd [2] 63 e5 [2] 24 e7 [2] 63 f6 [2] 2d fa [2] 21 f0 [2] 36 fb [2] 2d b5 [2] 10 }

  condition:
    any of them
}