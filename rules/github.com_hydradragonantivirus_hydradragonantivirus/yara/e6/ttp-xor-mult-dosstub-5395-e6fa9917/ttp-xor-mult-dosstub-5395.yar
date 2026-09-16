rule TTP_XOR_MULT_DOSStub_5395 {
  strings:
    $key_5395 = { 07 fd [2] 73 e5 [2] 34 e7 [2] 73 f6 [2] 3d fa [2] 31 f0 [2] 26 fb [2] 3d b5 [2] 00 }

  condition:
    any of them
}