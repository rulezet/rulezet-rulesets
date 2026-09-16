rule TTP_XOR_MULT_DOSStub_edbb {
  strings:
    $key_edbb = { b9 d3 [2] cd cb [2] 8a c9 [2] cd d8 [2] 83 d4 [2] 8f de [2] 98 d5 [2] 83 9b [2] be }

  condition:
    any of them
}