rule TTP_XOR_MULT_DOSStub_d477 {
  strings:
    $key_d477 = { 80 1f [2] f4 07 [2] b3 05 [2] f4 14 [2] ba 18 [2] b6 12 [2] a1 19 [2] ba 57 [2] 87 }

  condition:
    any of them
}