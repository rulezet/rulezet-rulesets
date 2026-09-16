rule TTP_XOR_MULT_DOSStub_f5b6 {
  strings:
    $key_f5b6 = { a1 de [2] d5 c6 [2] 92 c4 [2] d5 d5 [2] 9b d9 [2] 97 d3 [2] 80 d8 [2] 9b 96 [2] a6 }

  condition:
    any of them
}