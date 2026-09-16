rule TTP_XOR_MULT_DOSStub_d193 {
  strings:
    $key_d193 = { 85 fb [2] f1 e3 [2] b6 e1 [2] f1 f0 [2] bf fc [2] b3 f6 [2] a4 fd [2] bf b3 [2] 82 }

  condition:
    any of them
}