rule TTP_XOR_MULT_DOSStub_0c36 {
  strings:
    $key_0c36 = { 58 5e [2] 2c 46 [2] 6b 44 [2] 2c 55 [2] 62 59 [2] 6e 53 [2] 79 58 [2] 62 16 [2] 5f }

  condition:
    any of them
}