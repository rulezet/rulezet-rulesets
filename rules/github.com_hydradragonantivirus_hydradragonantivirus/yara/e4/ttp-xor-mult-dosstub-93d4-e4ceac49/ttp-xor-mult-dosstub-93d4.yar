rule TTP_XOR_MULT_DOSStub_93d4 {
  strings:
    $key_93d4 = { c7 bc [2] b3 a4 [2] f4 a6 [2] b3 b7 [2] fd bb [2] f1 b1 [2] e6 ba [2] fd f4 [2] c0 }

  condition:
    any of them
}