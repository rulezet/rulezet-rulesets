rule TTP_XOR_MULT_DOSStub_d4d9 {
  strings:
    $key_d4d9 = { 80 b1 [2] f4 a9 [2] b3 ab [2] f4 ba [2] ba b6 [2] b6 bc [2] a1 b7 [2] ba f9 [2] 87 }

  condition:
    any of them
}