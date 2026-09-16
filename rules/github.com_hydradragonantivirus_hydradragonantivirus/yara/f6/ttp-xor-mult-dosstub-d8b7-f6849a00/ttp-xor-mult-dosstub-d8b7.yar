rule TTP_XOR_MULT_DOSStub_d8b7 {
  strings:
    $key_d8b7 = { 8c df [2] f8 c7 [2] bf c5 [2] f8 d4 [2] b6 d8 [2] ba d2 [2] ad d9 [2] b6 97 [2] 8b }

  condition:
    any of them
}