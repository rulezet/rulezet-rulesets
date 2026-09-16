rule TTP_XOR_MULT_DOSStub_9794 {
  strings:
    $key_9794 = { c3 fc [2] b7 e4 [2] f0 e6 [2] b7 f7 [2] f9 fb [2] f5 f1 [2] e2 fa [2] f9 b4 [2] c4 }

  condition:
    any of them
}