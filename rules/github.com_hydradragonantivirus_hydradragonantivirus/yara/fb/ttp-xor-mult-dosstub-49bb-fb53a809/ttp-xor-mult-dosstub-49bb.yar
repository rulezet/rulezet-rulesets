rule TTP_XOR_MULT_DOSStub_49bb {
  strings:
    $key_49bb = { 1d d3 [2] 69 cb [2] 2e c9 [2] 69 d8 [2] 27 d4 [2] 2b de [2] 3c d5 [2] 27 9b [2] 1a }

  condition:
    any of them
}