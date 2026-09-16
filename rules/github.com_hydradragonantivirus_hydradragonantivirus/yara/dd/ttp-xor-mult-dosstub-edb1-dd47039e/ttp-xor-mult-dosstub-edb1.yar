rule TTP_XOR_MULT_DOSStub_edb1 {
  strings:
    $key_edb1 = { b9 d9 [2] cd c1 [2] 8a c3 [2] cd d2 [2] 83 de [2] 8f d4 [2] 98 df [2] 83 91 [2] be }

  condition:
    any of them
}