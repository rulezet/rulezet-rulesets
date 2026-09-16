rule TTP_XOR_MULT_DOSStub_d8d1 {
  strings:
    $key_d8d1 = { 8c b9 [2] f8 a1 [2] bf a3 [2] f8 b2 [2] b6 be [2] ba b4 [2] ad bf [2] b6 f1 [2] 8b }

  condition:
    any of them
}