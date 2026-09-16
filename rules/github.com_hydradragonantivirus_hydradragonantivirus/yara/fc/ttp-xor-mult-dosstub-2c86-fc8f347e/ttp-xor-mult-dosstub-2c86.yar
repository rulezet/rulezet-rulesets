rule TTP_XOR_MULT_DOSStub_2c86 {
  strings:
    $key_2c86 = { 78 ee [2] 0c f6 [2] 4b f4 [2] 0c e5 [2] 42 e9 [2] 4e e3 [2] 59 e8 [2] 42 a6 [2] 7f }

  condition:
    any of them
}