rule TTP_XOR_MULT_DOSStub_b8b5 {
  strings:
    $key_b8b5 = { ec dd [2] 98 c5 [2] df c7 [2] 98 d6 [2] d6 da [2] da d0 [2] cd db [2] d6 95 [2] eb }

  condition:
    any of them
}