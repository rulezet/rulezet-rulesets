rule TTP_XOR_MULT_DOSStub_63b1 {
  strings:
    $key_63b1 = { 37 d9 [2] 43 c1 [2] 04 c3 [2] 43 d2 [2] 0d de [2] 01 d4 [2] 16 df [2] 0d 91 [2] 30 }

  condition:
    any of them
}