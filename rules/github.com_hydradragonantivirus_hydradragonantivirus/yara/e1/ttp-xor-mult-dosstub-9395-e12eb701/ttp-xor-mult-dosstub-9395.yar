rule TTP_XOR_MULT_DOSStub_9395 {
  strings:
    $key_9395 = { c7 fd [2] b3 e5 [2] f4 e7 [2] b3 f6 [2] fd fa [2] f1 f0 [2] e6 fb [2] fd b5 [2] c0 }

  condition:
    any of them
}