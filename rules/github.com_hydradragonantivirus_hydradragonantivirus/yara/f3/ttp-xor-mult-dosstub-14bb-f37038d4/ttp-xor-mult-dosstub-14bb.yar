rule TTP_XOR_MULT_DOSStub_14bb {
  strings:
    $key_14bb = { 40 d3 [2] 34 cb [2] 73 c9 [2] 34 d8 [2] 7a d4 [2] 76 de [2] 61 d5 [2] 7a 9b [2] 47 }

  condition:
    any of them
}