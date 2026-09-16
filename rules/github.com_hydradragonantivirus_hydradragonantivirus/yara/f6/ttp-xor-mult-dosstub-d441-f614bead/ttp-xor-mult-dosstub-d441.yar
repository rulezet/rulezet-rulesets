rule TTP_XOR_MULT_DOSStub_d441 {
  strings:
    $key_d441 = { 80 29 [2] f4 31 [2] b3 33 [2] f4 22 [2] ba 2e [2] b6 24 [2] a1 2f [2] ba 61 [2] 87 }

  condition:
    any of them
}