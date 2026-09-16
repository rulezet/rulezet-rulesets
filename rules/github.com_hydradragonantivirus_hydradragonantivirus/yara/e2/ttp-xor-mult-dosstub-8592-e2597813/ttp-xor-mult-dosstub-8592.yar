rule TTP_XOR_MULT_DOSStub_8592 {
  strings:
    $key_8592 = { d1 fa [2] a5 e2 [2] e2 e0 [2] a5 f1 [2] eb fd [2] e7 f7 [2] f0 fc [2] eb b2 [2] d6 }

  condition:
    any of them
}