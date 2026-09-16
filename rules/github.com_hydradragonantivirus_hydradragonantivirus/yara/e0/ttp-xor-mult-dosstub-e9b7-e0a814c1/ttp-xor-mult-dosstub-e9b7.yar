rule TTP_XOR_MULT_DOSStub_e9b7 {
  strings:
    $key_e9b7 = { bd df [2] c9 c7 [2] 8e c5 [2] c9 d4 [2] 87 d8 [2] 8b d2 [2] 9c d9 [2] 87 97 [2] ba }

  condition:
    any of them
}