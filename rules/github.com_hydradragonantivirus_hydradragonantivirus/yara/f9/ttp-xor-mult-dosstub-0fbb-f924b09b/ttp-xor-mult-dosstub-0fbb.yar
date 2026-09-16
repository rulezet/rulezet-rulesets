rule TTP_XOR_MULT_DOSStub_0fbb {
  strings:
    $key_0fbb = { 5b d3 [2] 2f cb [2] 68 c9 [2] 2f d8 [2] 61 d4 [2] 6d de [2] 7a d5 [2] 61 9b [2] 5c }

  condition:
    any of them
}