rule TTP_XOR_MULT_DOSStub_d407 {
  strings:
    $key_d407 = { 80 6f [2] f4 77 [2] b3 75 [2] f4 64 [2] ba 68 [2] b6 62 [2] a1 69 [2] ba 27 [2] 87 }

  condition:
    any of them
}