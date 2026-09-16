rule TTP_XOR_MULT_DOSStub_9085 {
  strings:
    $key_9085 = { c4 ed [2] b0 f5 [2] f7 f7 [2] b0 e6 [2] fe ea [2] f2 e0 [2] e5 eb [2] fe a5 [2] c3 }

  condition:
    any of them
}