rule TTP_XOR_MULT_DOSStub_0c7a {
  strings:
    $key_0c7a = { 58 12 [2] 2c 0a [2] 6b 08 [2] 2c 19 [2] 62 15 [2] 6e 1f [2] 79 14 [2] 62 5a [2] 5f }

  condition:
    any of them
}