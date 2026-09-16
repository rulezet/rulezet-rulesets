rule TTP_XOR_MULT_DOSStub_0c1b {
  strings:
    $key_0c1b = { 58 73 [2] 2c 6b [2] 6b 69 [2] 2c 78 [2] 62 74 [2] 6e 7e [2] 79 75 [2] 62 3b [2] 5f }

  condition:
    any of them
}