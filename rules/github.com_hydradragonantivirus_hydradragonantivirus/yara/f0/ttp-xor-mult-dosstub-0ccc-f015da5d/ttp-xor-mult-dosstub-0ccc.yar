rule TTP_XOR_MULT_DOSStub_0ccc {
  strings:
    $key_0ccc = { 58 a4 [2] 2c bc [2] 6b be [2] 2c af [2] 62 a3 [2] 6e a9 [2] 79 a2 [2] 62 ec [2] 5f }

  condition:
    any of them
}