rule TTP_XOR_MULT_DOSStub_d4e1 {
  strings:
    $key_d4e1 = { 80 89 [2] f4 91 [2] b3 93 [2] f4 82 [2] ba 8e [2] b6 84 [2] a1 8f [2] ba c1 [2] 87 }

  condition:
    any of them
}