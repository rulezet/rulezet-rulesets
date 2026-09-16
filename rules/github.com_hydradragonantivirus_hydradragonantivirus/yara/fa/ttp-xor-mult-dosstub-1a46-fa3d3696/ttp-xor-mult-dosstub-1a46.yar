rule TTP_XOR_MULT_DOSStub_1a46 {
  strings:
    $key_1a46 = { 4e 2e [2] 3a 36 [2] 7d 34 [2] 3a 25 [2] 74 29 [2] 78 23 [2] 6f 28 [2] 74 66 [2] 49 }

  condition:
    any of them
}