rule TTP_XOR_MULT_DOSStub_0c42 {
  strings:
    $key_0c42 = { 58 2a [2] 2c 32 [2] 6b 30 [2] 2c 21 [2] 62 2d [2] 6e 27 [2] 79 2c [2] 62 62 [2] 5f }

  condition:
    any of them
}