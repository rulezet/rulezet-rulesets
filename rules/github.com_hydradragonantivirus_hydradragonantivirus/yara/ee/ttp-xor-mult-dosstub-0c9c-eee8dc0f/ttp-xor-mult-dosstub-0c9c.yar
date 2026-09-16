rule TTP_XOR_MULT_DOSStub_0c9c {
  strings:
    $key_0c9c = { 58 f4 [2] 2c ec [2] 6b ee [2] 2c ff [2] 62 f3 [2] 6e f9 [2] 79 f2 [2] 62 bc [2] 5f }

  condition:
    any of them
}