rule TTP_XOR_MULT_DOSStub_93d0 {
  strings:
    $key_93d0 = { c7 b8 [2] b3 a0 [2] f4 a2 [2] b3 b3 [2] fd bf [2] f1 b5 [2] e6 be [2] fd f0 [2] c0 }

  condition:
    any of them
}