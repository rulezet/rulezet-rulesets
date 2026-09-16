rule TTP_XOR_MULT_DOSStub_e9b6 {
  strings:
    $key_e9b6 = { bd de [2] c9 c6 [2] 8e c4 [2] c9 d5 [2] 87 d9 [2] 8b d3 [2] 9c d8 [2] 87 96 [2] ba }

  condition:
    any of them
}