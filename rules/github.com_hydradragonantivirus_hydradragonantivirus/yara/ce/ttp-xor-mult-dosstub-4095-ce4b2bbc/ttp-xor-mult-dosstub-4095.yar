rule TTP_XOR_MULT_DOSStub_4095 {
  strings:
    $key_4095 = { 14 fd [2] 60 e5 [2] 27 e7 [2] 60 f6 [2] 2e fa [2] 22 f0 [2] 35 fb [2] 2e b5 [2] 13 }

  condition:
    any of them
}