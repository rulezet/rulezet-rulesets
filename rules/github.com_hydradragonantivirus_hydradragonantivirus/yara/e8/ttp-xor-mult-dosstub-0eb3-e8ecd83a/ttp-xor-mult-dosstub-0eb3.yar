rule TTP_XOR_MULT_DOSStub_0eb3 {
  strings:
    $key_0eb3 = { 5a db [2] 2e c3 [2] 69 c1 [2] 2e d0 [2] 60 dc [2] 6c d6 [2] 7b dd [2] 60 93 [2] 5d }

  condition:
    any of them
}