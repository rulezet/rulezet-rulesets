rule TTP_XOR_MULT_DOSStub_98b6 {
  strings:
    $key_98b6 = { cc de [2] b8 c6 [2] ff c4 [2] b8 d5 [2] f6 d9 [2] fa d3 [2] ed d8 [2] f6 96 [2] cb }

  condition:
    any of them
}