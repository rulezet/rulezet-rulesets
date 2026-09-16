rule TTP_XOR_MULT_DOSStub_d4d7 {
  strings:
    $key_d4d7 = { 80 bf [2] f4 a7 [2] b3 a5 [2] f4 b4 [2] ba b8 [2] b6 b2 [2] a1 b9 [2] ba f7 [2] 87 }

  condition:
    any of them
}