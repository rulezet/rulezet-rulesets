rule TTP_XOR_MULT_DOSStub_8595 {
  strings:
    $key_8595 = { d1 fd [2] a5 e5 [2] e2 e7 [2] a5 f6 [2] eb fa [2] e7 f0 [2] f0 fb [2] eb b5 [2] d6 }

  condition:
    any of them
}