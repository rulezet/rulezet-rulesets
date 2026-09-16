rule TTP_XOR_MULT_DOSStub_2eb3 {
  strings:
    $key_2eb3 = { 7a db [2] 0e c3 [2] 49 c1 [2] 0e d0 [2] 40 dc [2] 4c d6 [2] 5b dd [2] 40 93 [2] 7d }

  condition:
    any of them
}