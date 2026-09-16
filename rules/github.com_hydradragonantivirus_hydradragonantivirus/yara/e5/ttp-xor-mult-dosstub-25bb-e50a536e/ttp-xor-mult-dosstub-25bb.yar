rule TTP_XOR_MULT_DOSStub_25bb {
  strings:
    $key_25bb = { 71 d3 [2] 05 cb [2] 42 c9 [2] 05 d8 [2] 4b d4 [2] 47 de [2] 50 d5 [2] 4b 9b [2] 76 }

  condition:
    any of them
}