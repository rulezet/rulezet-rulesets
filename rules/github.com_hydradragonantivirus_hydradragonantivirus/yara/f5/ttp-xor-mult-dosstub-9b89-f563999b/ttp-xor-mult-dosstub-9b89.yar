rule TTP_XOR_MULT_DOSStub_9b89 {
  strings:
    $key_9b89 = { cf e1 [2] bb f9 [2] fc fb [2] bb ea [2] f5 e6 [2] f9 ec [2] ee e7 [2] f5 a9 [2] c8 }

  condition:
    any of them
}