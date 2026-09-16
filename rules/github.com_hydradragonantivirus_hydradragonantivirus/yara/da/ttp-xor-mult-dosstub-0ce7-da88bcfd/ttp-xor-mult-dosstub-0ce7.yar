rule TTP_XOR_MULT_DOSStub_0ce7 {
  strings:
    $key_0ce7 = { 58 8f [2] 2c 97 [2] 6b 95 [2] 2c 84 [2] 62 88 [2] 6e 82 [2] 79 89 [2] 62 c7 [2] 5f }

  condition:
    any of them
}