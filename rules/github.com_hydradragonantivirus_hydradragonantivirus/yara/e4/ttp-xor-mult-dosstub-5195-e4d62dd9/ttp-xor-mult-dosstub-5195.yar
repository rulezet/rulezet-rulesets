rule TTP_XOR_MULT_DOSStub_5195 {
  strings:
    $key_5195 = { 05 fd [2] 71 e5 [2] 36 e7 [2] 71 f6 [2] 3f fa [2] 33 f0 [2] 24 fb [2] 3f b5 [2] 02 }

  condition:
    any of them
}