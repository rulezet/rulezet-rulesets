rule TTP_XOR_MULT_DOSStub_5983 {
  strings:
    $key_5983 = { 0d eb [2] 79 f3 [2] 3e f1 [2] 79 e0 [2] 37 ec [2] 3b e6 [2] 2c ed [2] 37 a3 [2] 0a }

  condition:
    any of them
}