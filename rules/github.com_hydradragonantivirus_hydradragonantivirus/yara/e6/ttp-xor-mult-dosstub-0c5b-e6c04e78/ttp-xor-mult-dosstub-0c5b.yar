rule TTP_XOR_MULT_DOSStub_0c5b {
  strings:
    $key_0c5b = { 58 33 [2] 2c 2b [2] 6b 29 [2] 2c 38 [2] 62 34 [2] 6e 3e [2] 79 35 [2] 62 7b [2] 5f }

  condition:
    any of them
}