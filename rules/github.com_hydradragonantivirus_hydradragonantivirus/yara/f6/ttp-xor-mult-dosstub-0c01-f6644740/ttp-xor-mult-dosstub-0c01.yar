rule TTP_XOR_MULT_DOSStub_0c01 {
  strings:
    $key_0c01 = { 58 69 [2] 2c 71 [2] 6b 73 [2] 2c 62 [2] 62 6e [2] 6e 64 [2] 79 6f [2] 62 21 [2] 5f }

  condition:
    any of them
}