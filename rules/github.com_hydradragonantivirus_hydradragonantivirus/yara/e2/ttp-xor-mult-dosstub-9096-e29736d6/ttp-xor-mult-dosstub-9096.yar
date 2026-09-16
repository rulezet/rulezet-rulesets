rule TTP_XOR_MULT_DOSStub_9096 {
  strings:
    $key_9096 = { c4 fe [2] b0 e6 [2] f7 e4 [2] b0 f5 [2] fe f9 [2] f2 f3 [2] e5 f8 [2] fe b6 [2] c3 }

  condition:
    any of them
}