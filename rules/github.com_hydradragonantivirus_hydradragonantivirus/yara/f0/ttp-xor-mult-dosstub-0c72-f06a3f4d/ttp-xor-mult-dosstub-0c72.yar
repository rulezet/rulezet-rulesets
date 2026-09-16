rule TTP_XOR_MULT_DOSStub_0c72 {
  strings:
    $key_0c72 = { 58 1a [2] 2c 02 [2] 6b 00 [2] 2c 11 [2] 62 1d [2] 6e 17 [2] 79 1c [2] 62 52 [2] 5f }

  condition:
    any of them
}