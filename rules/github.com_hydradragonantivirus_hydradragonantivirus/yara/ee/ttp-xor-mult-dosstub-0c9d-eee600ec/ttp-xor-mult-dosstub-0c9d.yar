rule TTP_XOR_MULT_DOSStub_0c9d {
  strings:
    $key_0c9d = { 58 f5 [2] 2c ed [2] 6b ef [2] 2c fe [2] 62 f2 [2] 6e f8 [2] 79 f3 [2] 62 bd [2] 5f }

  condition:
    any of them
}