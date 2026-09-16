rule TTP_XOR_MULT_DOSStub_93d9 {
  strings:
    $key_93d9 = { c7 b1 [2] b3 a9 [2] f4 ab [2] b3 ba [2] fd b6 [2] f1 bc [2] e6 b7 [2] fd f9 [2] c0 }

  condition:
    any of them
}