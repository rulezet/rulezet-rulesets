rule TTP_XOR_MULT_DOSStub_edb4 {
  strings:
    $key_edb4 = { b9 dc [2] cd c4 [2] 8a c6 [2] cd d7 [2] 83 db [2] 8f d1 [2] 98 da [2] 83 94 [2] be }

  condition:
    any of them
}