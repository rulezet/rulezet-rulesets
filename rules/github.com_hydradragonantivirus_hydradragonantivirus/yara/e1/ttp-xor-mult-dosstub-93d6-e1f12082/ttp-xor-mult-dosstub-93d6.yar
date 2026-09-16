rule TTP_XOR_MULT_DOSStub_93d6 {
  strings:
    $key_93d6 = { c7 be [2] b3 a6 [2] f4 a4 [2] b3 b5 [2] fd b9 [2] f1 b3 [2] e6 b8 [2] fd f6 [2] c0 }

  condition:
    any of them
}