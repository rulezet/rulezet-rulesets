rule TTP_XOR_MULT_DOSStub_78ca {
  strings:
    $key_78ca = { 2c a2 [2] 58 ba [2] 1f b8 [2] 58 a9 [2] 16 a5 [2] 1a af [2] 0d a4 [2] 16 ea [2] 2b }

  condition:
    any of them
}