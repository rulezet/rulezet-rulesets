rule TTP_XOR_MULT_DOSStub_5eb3 {
  strings:
    $key_5eb3 = { 0a db [2] 7e c3 [2] 39 c1 [2] 7e d0 [2] 30 dc [2] 3c d6 [2] 2b dd [2] 30 93 [2] 0d }

  condition:
    any of them
}