rule TTP_XOR_MULT_DOSStub_95d4 {
  strings:
    $key_95d4 = { c1 bc [2] b5 a4 [2] f2 a6 [2] b5 b7 [2] fb bb [2] f7 b1 [2] e0 ba [2] fb f4 [2] c6 }

  condition:
    any of them
}