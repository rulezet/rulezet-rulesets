rule TTP_XOR_MULT_DOSStub_7885 {
  strings:
    $key_7885 = { 2c ed [2] 58 f5 [2] 1f f7 [2] 58 e6 [2] 16 ea [2] 1a e0 [2] 0d eb [2] 16 a5 [2] 2b }

  condition:
    any of them
}