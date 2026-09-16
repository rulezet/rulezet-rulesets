rule TTP_XOR_MULT_DOSStub_4dbb {
  strings:
    $key_4dbb = { 19 d3 [2] 6d cb [2] 2a c9 [2] 6d d8 [2] 23 d4 [2] 2f de [2] 38 d5 [2] 23 9b [2] 1e }

  condition:
    any of them
}