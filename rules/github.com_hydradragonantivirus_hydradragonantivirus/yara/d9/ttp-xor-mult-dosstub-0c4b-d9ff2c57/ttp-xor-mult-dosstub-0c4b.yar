rule TTP_XOR_MULT_DOSStub_0c4b {
  strings:
    $key_0c4b = { 58 23 [2] 2c 3b [2] 6b 39 [2] 2c 28 [2] 62 24 [2] 6e 2e [2] 79 25 [2] 62 6b [2] 5f }

  condition:
    any of them
}