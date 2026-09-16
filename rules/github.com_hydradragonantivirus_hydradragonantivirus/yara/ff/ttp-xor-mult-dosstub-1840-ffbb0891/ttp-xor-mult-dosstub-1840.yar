rule TTP_XOR_MULT_DOSStub_1840 {
  strings:
    $key_1840 = { 4c 28 [2] 38 30 [2] 7f 32 [2] 38 23 [2] 76 2f [2] 7a 25 [2] 6d 2e [2] 76 60 [2] 4b }

  condition:
    any of them
}