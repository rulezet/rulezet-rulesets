rule TTP_XOR_MULT_DOSStub_d198 {
  strings:
    $key_d198 = { 85 f0 [2] f1 e8 [2] b6 ea [2] f1 fb [2] bf f7 [2] b3 fd [2] a4 f6 [2] bf b8 [2] 82 }

  condition:
    any of them
}