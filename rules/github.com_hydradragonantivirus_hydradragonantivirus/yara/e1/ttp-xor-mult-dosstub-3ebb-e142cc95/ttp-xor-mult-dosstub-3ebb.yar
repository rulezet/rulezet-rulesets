rule TTP_XOR_MULT_DOSStub_3ebb {
  strings:
    $key_3ebb = { 6a d3 [2] 1e cb [2] 59 c9 [2] 1e d8 [2] 50 d4 [2] 5c de [2] 4b d5 [2] 50 9b [2] 6d }

  condition:
    any of them
}