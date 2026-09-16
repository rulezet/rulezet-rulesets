rule TTP_XOR_MULT_DOSStub_d8c6 {
  strings:
    $key_d8c6 = { 8c ae [2] f8 b6 [2] bf b4 [2] f8 a5 [2] b6 a9 [2] ba a3 [2] ad a8 [2] b6 e6 [2] 8b }

  condition:
    any of them
}