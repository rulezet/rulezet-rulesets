rule TTP_XOR_MULT_DOSStub_acbb {
  strings:
    $key_acbb = { f8 d3 [2] 8c cb [2] cb c9 [2] 8c d8 [2] c2 d4 [2] ce de [2] d9 d5 [2] c2 9b [2] ff }

  condition:
    any of them
}