rule TTP_XOR_MULT_DOSStub_30bb {
  strings:
    $key_30bb = { 64 d3 [2] 10 cb [2] 57 c9 [2] 10 d8 [2] 5e d4 [2] 52 de [2] 45 d5 [2] 5e 9b [2] 63 }

  condition:
    any of them
}