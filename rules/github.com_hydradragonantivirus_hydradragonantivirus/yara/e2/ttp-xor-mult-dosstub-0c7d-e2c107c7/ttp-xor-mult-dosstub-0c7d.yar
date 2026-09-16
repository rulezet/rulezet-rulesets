rule TTP_XOR_MULT_DOSStub_0c7d {
  strings:
    $key_0c7d = { 58 15 [2] 2c 0d [2] 6b 0f [2] 2c 1e [2] 62 12 [2] 6e 18 [2] 79 13 [2] 62 5d [2] 5f }

  condition:
    any of them
}