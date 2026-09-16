rule TTP_XOR_MULT_DOSStub_9b88 {
  strings:
    $key_9b88 = { cf e0 [2] bb f8 [2] fc fa [2] bb eb [2] f5 e7 [2] f9 ed [2] ee e6 [2] f5 a8 [2] c8 }

  condition:
    any of them
}