rule TTP_XOR_MULT_DOSStub_edb3 {
  strings:
    $key_edb3 = { b9 db [2] cd c3 [2] 8a c1 [2] cd d0 [2] 83 dc [2] 8f d6 [2] 98 dd [2] 83 93 [2] be }

  condition:
    any of them
}