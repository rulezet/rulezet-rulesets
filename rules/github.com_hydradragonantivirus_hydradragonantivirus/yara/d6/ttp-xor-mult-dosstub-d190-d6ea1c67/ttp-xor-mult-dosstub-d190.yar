rule TTP_XOR_MULT_DOSStub_d190 {
  strings:
    $key_d190 = { 85 f8 [2] f1 e0 [2] b6 e2 [2] f1 f3 [2] bf ff [2] b3 f5 [2] a4 fe [2] bf b0 [2] 82 }

  condition:
    any of them
}