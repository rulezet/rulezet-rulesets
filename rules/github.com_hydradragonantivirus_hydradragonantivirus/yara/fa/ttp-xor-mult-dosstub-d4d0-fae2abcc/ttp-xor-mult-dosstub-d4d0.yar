rule TTP_XOR_MULT_DOSStub_d4d0 {
  strings:
    $key_d4d0 = { 80 b8 [2] f4 a0 [2] b3 a2 [2] f4 b3 [2] ba bf [2] b6 b5 [2] a1 be [2] ba f0 [2] 87 }

  condition:
    any of them
}