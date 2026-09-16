rule TTP_XOR_MULT_DOSStub_3eb5 {
  strings:
    $key_3eb5 = { 6a dd [2] 1e c5 [2] 59 c7 [2] 1e d6 [2] 50 da [2] 5c d0 [2] 4b db [2] 50 95 [2] 6d }

  condition:
    any of them
}