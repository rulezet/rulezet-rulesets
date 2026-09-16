rule TTP_XOR_MULT_DOSStub_0c07 {
  strings:
    $key_0c07 = { 58 6f [2] 2c 77 [2] 6b 75 [2] 2c 64 [2] 62 68 [2] 6e 62 [2] 79 69 [2] 62 27 [2] 5f }

  condition:
    any of them
}