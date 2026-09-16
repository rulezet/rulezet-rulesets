rule TTP_XOR_MULT_DOSStub_9598 {
  strings:
    $key_9598 = { c1 f0 [2] b5 e8 [2] f2 ea [2] b5 fb [2] fb f7 [2] f7 fd [2] e0 f6 [2] fb b8 [2] c6 }

  condition:
    any of them
}