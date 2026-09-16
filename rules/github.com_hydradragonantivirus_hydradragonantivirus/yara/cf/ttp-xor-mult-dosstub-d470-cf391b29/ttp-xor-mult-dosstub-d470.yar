rule TTP_XOR_MULT_DOSStub_d470 {
  strings:
    $key_d470 = { 80 18 [2] f4 00 [2] b3 02 [2] f4 13 [2] ba 1f [2] b6 15 [2] a1 1e [2] ba 50 [2] 87 }

  condition:
    any of them
}