rule TTP_XOR_MULT_DOSStub_1c46 {
  strings:
    $key_1c46 = { 48 2e [2] 3c 36 [2] 7b 34 [2] 3c 25 [2] 72 29 [2] 7e 23 [2] 69 28 [2] 72 66 [2] 4f }

  condition:
    any of them
}