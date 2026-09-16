rule TTP_XOR_MULT_DOSStub_7ab7 {
  strings:
    $key_7ab7 = { 2e df [2] 5a c7 [2] 1d c5 [2] 5a d4 [2] 14 d8 [2] 18 d2 [2] 0f d9 [2] 14 97 [2] 29 }

  condition:
    any of them
}