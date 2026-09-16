rule TTP_XOR_MULT_DOSStub_edb6 {
  strings:
    $key_edb6 = { b9 de [2] cd c6 [2] 8a c4 [2] cd d5 [2] 83 d9 [2] 8f d3 [2] 98 d8 [2] 83 96 [2] be }

  condition:
    any of them
}