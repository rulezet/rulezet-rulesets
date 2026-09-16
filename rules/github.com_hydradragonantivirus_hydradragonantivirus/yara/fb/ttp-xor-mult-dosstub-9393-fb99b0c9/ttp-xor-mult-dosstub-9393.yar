rule TTP_XOR_MULT_DOSStub_9393 {
  strings:
    $key_9393 = { c7 fb [2] b3 e3 [2] f4 e1 [2] b3 f0 [2] fd fc [2] f1 f6 [2] e6 fd [2] fd b3 [2] c0 }

  condition:
    any of them
}