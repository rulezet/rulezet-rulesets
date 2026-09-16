rule TTP_XOR_MULT_DOSStub_93d7 {
  strings:
    $key_93d7 = { c7 bf [2] b3 a7 [2] f4 a5 [2] b3 b4 [2] fd b8 [2] f1 b2 [2] e6 b9 [2] fd f7 [2] c0 }

  condition:
    any of them
}