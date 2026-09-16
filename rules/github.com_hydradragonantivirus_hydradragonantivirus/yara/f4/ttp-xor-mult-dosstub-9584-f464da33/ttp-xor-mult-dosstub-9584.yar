rule TTP_XOR_MULT_DOSStub_9584 {
  strings:
    $key_9584 = { c1 ec [2] b5 f4 [2] f2 f6 [2] b5 e7 [2] fb eb [2] f7 e1 [2] e0 ea [2] fb a4 [2] c6 }

  condition:
    any of them
}