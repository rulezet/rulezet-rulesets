rule TTP_XOR_MULT_DOSStub_45b1 {
  strings:
    $key_45b1 = { 11 d9 [2] 65 c1 [2] 22 c3 [2] 65 d2 [2] 2b de [2] 27 d4 [2] 30 df [2] 2b 91 [2] 16 }

  condition:
    any of them
}