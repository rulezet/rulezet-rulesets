rule TTP_XOR_MULT_DOSStub_0c21 {
  strings:
    $key_0c21 = { 58 49 [2] 2c 51 [2] 6b 53 [2] 2c 42 [2] 62 4e [2] 6e 44 [2] 79 4f [2] 62 01 [2] 5f }

  condition:
    any of them
}