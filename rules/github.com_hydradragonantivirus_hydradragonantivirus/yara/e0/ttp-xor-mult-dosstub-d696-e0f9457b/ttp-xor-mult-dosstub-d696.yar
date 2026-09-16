rule TTP_XOR_MULT_DOSStub_d696 {
  strings:
    $key_d696 = { 82 fe [2] f6 e6 [2] b1 e4 [2] f6 f5 [2] b8 f9 [2] b4 f3 [2] a3 f8 [2] b8 b6 [2] 85 }

  condition:
    any of them
}