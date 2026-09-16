rule TTP_XOR_MULT_DOSStub_a795 {
  strings:
    $key_a795 = { f3 fd [2] 87 e5 [2] c0 e7 [2] 87 f6 [2] c9 fa [2] c5 f0 [2] d2 fb [2] c9 b5 [2] f4 }

  condition:
    any of them
}