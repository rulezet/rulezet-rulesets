rule TTP_XOR_MULT_DOSStub_2fbb {
  strings:
    $key_2fbb = { 7b d3 [2] 0f cb [2] 48 c9 [2] 0f d8 [2] 41 d4 [2] 4d de [2] 5a d5 [2] 41 9b [2] 7c }

  condition:
    any of them
}