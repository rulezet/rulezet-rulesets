rule TTP_XOR_MULT_DOSStub_65b6 {
  strings:
    $key_65b6 = { 31 de [2] 45 c6 [2] 02 c4 [2] 45 d5 [2] 0b d9 [2] 07 d3 [2] 10 d8 [2] 0b 96 [2] 36 }

  condition:
    any of them
}