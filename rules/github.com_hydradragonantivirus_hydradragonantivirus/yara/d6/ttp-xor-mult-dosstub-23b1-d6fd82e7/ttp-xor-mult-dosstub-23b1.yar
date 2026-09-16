rule TTP_XOR_MULT_DOSStub_23b1 {
  strings:
    $key_23b1 = { 77 d9 [2] 03 c1 [2] 44 c3 [2] 03 d2 [2] 4d de [2] 41 d4 [2] 56 df [2] 4d 91 [2] 70 }

  condition:
    any of them
}