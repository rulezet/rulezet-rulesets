rule TTP_XOR_MULT_DOSStub_0c5f {
  strings:
    $key_0c5f = { 58 37 [2] 2c 2f [2] 6b 2d [2] 2c 3c [2] 62 30 [2] 6e 3a [2] 79 31 [2] 62 7f [2] 5f }

  condition:
    any of them
}