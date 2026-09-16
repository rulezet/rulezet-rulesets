rule TTP_XOR_MULT_DOSStub_6395 {
  strings:
    $key_6395 = { 37 fd [2] 43 e5 [2] 04 e7 [2] 43 f6 [2] 0d fa [2] 01 f0 [2] 16 fb [2] 0d b5 [2] 30 }

  condition:
    any of them
}