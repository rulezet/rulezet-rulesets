rule TTP_XOR_MULT_DOSStub_d4b9 {
  strings:
    $key_d4b9 = { 80 d1 [2] f4 c9 [2] b3 cb [2] f4 da [2] ba d6 [2] b6 dc [2] a1 d7 [2] ba 99 [2] 87 }

  condition:
    any of them
}