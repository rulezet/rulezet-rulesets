rule TTP_XOR_MULT_DOSStub_0c6e {
  strings:
    $key_0c6e = { 58 06 [2] 2c 1e [2] 6b 1c [2] 2c 0d [2] 62 01 [2] 6e 0b [2] 79 00 [2] 62 4e [2] 5f }

  condition:
    any of them
}