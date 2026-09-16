rule TTP_XOR_MULT_DOSStub_b8bb {
  strings:
    $key_b8bb = { ec d3 [2] 98 cb [2] df c9 [2] 98 d8 [2] d6 d4 [2] da de [2] cd d5 [2] d6 9b [2] eb }

  condition:
    any of them
}