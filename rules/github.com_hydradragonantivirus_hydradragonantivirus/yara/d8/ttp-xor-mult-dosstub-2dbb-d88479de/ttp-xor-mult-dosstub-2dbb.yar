rule TTP_XOR_MULT_DOSStub_2dbb {
  strings:
    $key_2dbb = { 79 d3 [2] 0d cb [2] 4a c9 [2] 0d d8 [2] 43 d4 [2] 4f de [2] 58 d5 [2] 43 9b [2] 7e }

  condition:
    any of them
}