rule TTP_XOR_MULT_DOSStub_9493 {
  strings:
    $key_9493 = { c0 fb [2] b4 e3 [2] f3 e1 [2] b4 f0 [2] fa fc [2] f6 f6 [2] e1 fd [2] fa b3 [2] c7 }

  condition:
    any of them
}