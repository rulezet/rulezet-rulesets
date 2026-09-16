rule TTP_XOR_MULT_DOSStub_0c62 {
  strings:
    $key_0c62 = { 58 0a [2] 2c 12 [2] 6b 10 [2] 2c 01 [2] 62 0d [2] 6e 07 [2] 79 0c [2] 62 42 [2] 5f }

  condition:
    any of them
}