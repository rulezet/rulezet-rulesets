rule TTP_XOR_MULT_DOSStub_d436 {
  strings:
    $key_d436 = { 80 5e [2] f4 46 [2] b3 44 [2] f4 55 [2] ba 59 [2] b6 53 [2] a1 58 [2] ba 16 [2] 87 }

  condition:
    any of them
}