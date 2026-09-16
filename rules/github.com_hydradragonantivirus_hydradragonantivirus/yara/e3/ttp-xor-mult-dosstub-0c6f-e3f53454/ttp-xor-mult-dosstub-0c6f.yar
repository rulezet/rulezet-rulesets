rule TTP_XOR_MULT_DOSStub_0c6f {
  strings:
    $key_0c6f = { 58 07 [2] 2c 1f [2] 6b 1d [2] 2c 0c [2] 62 00 [2] 6e 0a [2] 79 01 [2] 62 4f [2] 5f }

  condition:
    any of them
}