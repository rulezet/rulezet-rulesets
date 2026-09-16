rule TTP_XOR_MULT_DOSStub_2eb7 {
  strings:
    $key_2eb7 = { 7a df [2] 0e c7 [2] 49 c5 [2] 0e d4 [2] 40 d8 [2] 4c d2 [2] 5b d9 [2] 40 97 [2] 7d }

  condition:
    any of them
}