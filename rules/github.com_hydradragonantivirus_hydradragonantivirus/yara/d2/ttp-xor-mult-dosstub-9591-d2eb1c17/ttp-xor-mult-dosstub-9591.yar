rule TTP_XOR_MULT_DOSStub_9591 {
  strings:
    $key_9591 = { c1 f9 [2] b5 e1 [2] f2 e3 [2] b5 f2 [2] fb fe [2] f7 f4 [2] e0 ff [2] fb b1 [2] c6 }

  condition:
    any of them
}