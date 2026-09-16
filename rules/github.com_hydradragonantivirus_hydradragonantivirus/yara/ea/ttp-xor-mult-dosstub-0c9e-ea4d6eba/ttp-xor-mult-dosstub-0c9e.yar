rule TTP_XOR_MULT_DOSStub_0c9e {
  strings:
    $key_0c9e = { 58 f6 [2] 2c ee [2] 6b ec [2] 2c fd [2] 62 f1 [2] 6e fb [2] 79 f0 [2] 62 be [2] 5f }

  condition:
    any of them
}