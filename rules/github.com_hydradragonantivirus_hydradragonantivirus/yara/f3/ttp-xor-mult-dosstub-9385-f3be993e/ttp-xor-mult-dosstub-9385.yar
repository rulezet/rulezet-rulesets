rule TTP_XOR_MULT_DOSStub_9385 {
  strings:
    $key_9385 = { c7 ed [2] b3 f5 [2] f4 f7 [2] b3 e6 [2] fd ea [2] f1 e0 [2] e6 eb [2] fd a5 [2] c0 }

  condition:
    any of them
}