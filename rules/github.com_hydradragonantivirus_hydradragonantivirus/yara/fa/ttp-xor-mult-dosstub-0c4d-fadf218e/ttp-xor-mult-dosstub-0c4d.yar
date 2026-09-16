rule TTP_XOR_MULT_DOSStub_0c4d {
  strings:
    $key_0c4d = { 58 25 [2] 2c 3d [2] 6b 3f [2] 2c 2e [2] 62 22 [2] 6e 28 [2] 79 23 [2] 62 6d [2] 5f }

  condition:
    any of them
}