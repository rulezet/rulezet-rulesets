rule TTP_XOR_MULT_DOSStub_bab6 {
  strings:
    $key_bab6 = { ee de [2] 9a c6 [2] dd c4 [2] 9a d5 [2] d4 d9 [2] d8 d3 [2] cf d8 [2] d4 96 [2] e9 }

  condition:
    any of them
}