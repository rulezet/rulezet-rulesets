rule TTP_XOR_MULT_DOSStub_0c51 {
  strings:
    $key_0c51 = { 58 39 [2] 2c 21 [2] 6b 23 [2] 2c 32 [2] 62 3e [2] 6e 34 [2] 79 3f [2] 62 71 [2] 5f }

  condition:
    any of them
}