rule TTP_XOR_MULT_DOSStub_9682 {
  strings:
    $key_9682 = { c2 ea [2] b6 f2 [2] f1 f0 [2] b6 e1 [2] f8 ed [2] f4 e7 [2] e3 ec [2] f8 a2 [2] c5 }

  condition:
    any of them
}