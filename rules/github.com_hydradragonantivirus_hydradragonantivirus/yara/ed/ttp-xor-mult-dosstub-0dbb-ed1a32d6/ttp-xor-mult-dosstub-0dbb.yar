rule TTP_XOR_MULT_DOSStub_0dbb {
  strings:
    $key_0dbb = { 59 d3 [2] 2d cb [2] 6a c9 [2] 2d d8 [2] 63 d4 [2] 6f de [2] 78 d5 [2] 63 9b [2] 5e }

  condition:
    any of them
}