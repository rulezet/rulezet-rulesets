rule TTP_XOR_MULT_DOSStub_4546 {
  strings:
    $key_4546 = { 11 2e [2] 65 36 [2] 22 34 [2] 65 25 [2] 2b 29 [2] 27 23 [2] 30 28 [2] 2b 66 [2] 16 }

  condition:
    any of them
}