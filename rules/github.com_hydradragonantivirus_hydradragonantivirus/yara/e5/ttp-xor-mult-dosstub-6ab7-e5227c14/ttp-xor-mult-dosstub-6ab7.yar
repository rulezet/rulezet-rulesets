rule TTP_XOR_MULT_DOSStub_6ab7 {
  strings:
    $key_6ab7 = { 3e df [2] 4a c7 [2] 0d c5 [2] 4a d4 [2] 04 d8 [2] 08 d2 [2] 1f d9 [2] 04 97 [2] 39 }

  condition:
    any of them
}