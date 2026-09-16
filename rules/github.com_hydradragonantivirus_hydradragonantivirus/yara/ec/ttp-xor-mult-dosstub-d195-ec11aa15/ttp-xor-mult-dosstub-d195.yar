rule TTP_XOR_MULT_DOSStub_d195 {
  strings:
    $key_d195 = { 85 fd [2] f1 e5 [2] b6 e7 [2] f1 f6 [2] bf fa [2] b3 f0 [2] a4 fb [2] bf b5 [2] 82 }

  condition:
    any of them
}