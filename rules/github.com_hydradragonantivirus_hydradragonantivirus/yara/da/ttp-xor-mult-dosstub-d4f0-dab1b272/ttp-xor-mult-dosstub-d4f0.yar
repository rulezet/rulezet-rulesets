rule TTP_XOR_MULT_DOSStub_d4f0 {
  strings:
    $key_d4f0 = { 80 98 [2] f4 80 [2] b3 82 [2] f4 93 [2] ba 9f [2] b6 95 [2] a1 9e [2] ba d0 [2] 87 }

  condition:
    any of them
}