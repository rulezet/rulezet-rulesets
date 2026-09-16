rule TTP_XOR_MULT_DOSStub_0c46 {
  strings:
    $key_0c46 = { 58 2e [2] 2c 36 [2] 6b 34 [2] 2c 25 [2] 62 29 [2] 6e 23 [2] 79 28 [2] 62 66 [2] 5f }

  condition:
    any of them
}