rule TTP_XOR_MULT_DOSStub_9795 {
  strings:
    $key_9795 = { c3 fd [2] b7 e5 [2] f0 e7 [2] b7 f6 [2] f9 fa [2] f5 f0 [2] e2 fb [2] f9 b5 [2] c4 }

  condition:
    any of them
}