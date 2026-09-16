rule TTP_XOR_MULT_DOSStub_0cca {
  strings:
    $key_0cca = { 58 a2 [2] 2c ba [2] 6b b8 [2] 2c a9 [2] 62 a5 [2] 6e af [2] 79 a4 [2] 62 ea [2] 5f }

  condition:
    any of them
}