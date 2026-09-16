rule TTP_XOR_MULT_DOSStub_d416 {
  strings:
    $key_d416 = { 80 7e [2] f4 66 [2] b3 64 [2] f4 75 [2] ba 79 [2] b6 73 [2] a1 78 [2] ba 36 [2] 87 }

  condition:
    any of them
}