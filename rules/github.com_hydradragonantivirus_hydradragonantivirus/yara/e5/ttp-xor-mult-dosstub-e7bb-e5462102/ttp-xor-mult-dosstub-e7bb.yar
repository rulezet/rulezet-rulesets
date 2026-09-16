rule TTP_XOR_MULT_DOSStub_e7bb {
  strings:
    $key_e7bb = { b3 d3 [2] c7 cb [2] 80 c9 [2] c7 d8 [2] 89 d4 [2] 85 de [2] 92 d5 [2] 89 9b [2] b4 }

  condition:
    any of them
}