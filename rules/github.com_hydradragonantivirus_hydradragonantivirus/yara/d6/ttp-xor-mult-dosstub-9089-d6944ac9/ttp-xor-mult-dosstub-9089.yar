rule TTP_XOR_MULT_DOSStub_9089 {
  strings:
    $key_9089 = { c4 e1 [2] b0 f9 [2] f7 fb [2] b0 ea [2] fe e6 [2] f2 ec [2] e5 e7 [2] fe a9 [2] c3 }

  condition:
    any of them
}