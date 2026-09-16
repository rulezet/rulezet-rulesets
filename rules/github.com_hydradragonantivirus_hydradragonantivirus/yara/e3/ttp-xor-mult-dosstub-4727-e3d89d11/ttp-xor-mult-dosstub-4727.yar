rule TTP_XOR_MULT_DOSStub_4727 {
  strings:
    $key_4727 = { 13 4f [2] 67 57 [2] 20 55 [2] 67 44 [2] 29 48 [2] 25 42 [2] 32 49 [2] 29 07 [2] 14 }

  condition:
    any of them
}