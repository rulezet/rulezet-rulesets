rule TTP_XOR_MULT_DOSStub_70f7 {
  strings:
    $key_70f7 = { 24 9f [2] 50 87 [2] 17 85 [2] 50 94 [2] 1e 98 [2] 12 92 [2] 05 99 [2] 1e d7 [2] 23 }

  condition:
    any of them
}