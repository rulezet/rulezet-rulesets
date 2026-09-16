rule TTP_XOR_MULT_DOSStub_7eb3 {
  strings:
    $key_7eb3 = { 2a db [2] 5e c3 [2] 19 c1 [2] 5e d0 [2] 10 dc [2] 1c d6 [2] 0b dd [2] 10 93 [2] 2d }

  condition:
    any of them
}