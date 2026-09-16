rule TTP_XOR_MULT_DOSStub_4eb5 {
  strings:
    $key_4eb5 = { 1a dd [2] 6e c5 [2] 29 c7 [2] 6e d6 [2] 20 da [2] 2c d0 [2] 3b db [2] 20 95 [2] 1d }

  condition:
    any of them
}