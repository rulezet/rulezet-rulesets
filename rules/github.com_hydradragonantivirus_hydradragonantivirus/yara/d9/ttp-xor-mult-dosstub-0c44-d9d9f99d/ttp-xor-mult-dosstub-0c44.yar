rule TTP_XOR_MULT_DOSStub_0c44 {
  strings:
    $key_0c44 = { 58 2c [2] 2c 34 [2] 6b 36 [2] 2c 27 [2] 62 2b [2] 6e 21 [2] 79 2a [2] 62 64 [2] 5f }

  condition:
    any of them
}