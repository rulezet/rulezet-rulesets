rule TTP_XOR_MULT_DOSStub_d486 {
  strings:
    $key_d486 = { 80 ee [2] f4 f6 [2] b3 f4 [2] f4 e5 [2] ba e9 [2] b6 e3 [2] a1 e8 [2] ba a6 [2] 87 }

  condition:
    any of them
}