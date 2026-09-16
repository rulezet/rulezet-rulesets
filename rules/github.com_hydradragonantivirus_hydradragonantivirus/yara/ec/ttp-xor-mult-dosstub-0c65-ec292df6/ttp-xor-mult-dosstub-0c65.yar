rule TTP_XOR_MULT_DOSStub_0c65 {
  strings:
    $key_0c65 = { 58 0d [2] 2c 15 [2] 6b 17 [2] 2c 06 [2] 62 0a [2] 6e 00 [2] 79 0b [2] 62 45 [2] 5f }

  condition:
    any of them
}