rule TTP_XOR_MULT_DOSStub_fbbb {
  strings:
    $key_fbbb = { af d3 [2] db cb [2] 9c c9 [2] db d8 [2] 95 d4 [2] 99 de [2] 8e d5 [2] 95 9b [2] a8 }

  condition:
    any of them
}