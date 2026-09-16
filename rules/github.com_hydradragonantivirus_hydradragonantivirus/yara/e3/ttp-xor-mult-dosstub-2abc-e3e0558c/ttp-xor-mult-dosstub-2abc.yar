rule TTP_XOR_MULT_DOSStub_2abc {
  strings:
    $key_2abc = { 7e d4 [2] 0a cc [2] 4d ce [2] 0a df [2] 44 d3 [2] 48 d9 [2] 5f d2 [2] 44 9c [2] 79 }

  condition:
    any of them
}