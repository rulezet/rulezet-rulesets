rule TTP_XOR_MULT_DOSStub_d497 {
  strings:
    $key_d497 = { 80 ff [2] f4 e7 [2] b3 e5 [2] f4 f4 [2] ba f8 [2] b6 f2 [2] a1 f9 [2] ba b7 [2] 87 }

  condition:
    any of them
}