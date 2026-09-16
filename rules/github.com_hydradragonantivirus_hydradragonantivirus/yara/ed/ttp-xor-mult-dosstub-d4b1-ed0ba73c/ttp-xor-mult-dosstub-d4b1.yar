rule TTP_XOR_MULT_DOSStub_d4b1 {
  strings:
    $key_d4b1 = { 80 d9 [2] f4 c1 [2] b3 c3 [2] f4 d2 [2] ba de [2] b6 d4 [2] a1 df [2] ba 91 [2] 87 }

  condition:
    any of them
}