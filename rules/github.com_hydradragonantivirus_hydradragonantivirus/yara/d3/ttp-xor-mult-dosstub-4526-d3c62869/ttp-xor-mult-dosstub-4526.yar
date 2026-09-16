rule TTP_XOR_MULT_DOSStub_4526 {
  strings:
    $key_4526 = { 11 4e [2] 65 56 [2] 22 54 [2] 65 45 [2] 2b 49 [2] 27 43 [2] 30 48 [2] 2b 06 [2] 16 }

  condition:
    any of them
}