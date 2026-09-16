rule TTP_XOR_MULT_DOSStub_0c27 {
  strings:
    $key_0c27 = { 58 4f [2] 2c 57 [2] 6b 55 [2] 2c 44 [2] 62 48 [2] 6e 42 [2] 79 49 [2] 62 07 [2] 5f }

  condition:
    any of them
}