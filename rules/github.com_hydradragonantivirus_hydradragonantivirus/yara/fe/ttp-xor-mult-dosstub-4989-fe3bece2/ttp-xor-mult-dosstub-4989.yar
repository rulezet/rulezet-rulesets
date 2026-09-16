rule TTP_XOR_MULT_DOSStub_4989 {
  strings:
    $key_4989 = { 1d e1 [2] 69 f9 [2] 2e fb [2] 69 ea [2] 27 e6 [2] 2b ec [2] 3c e7 [2] 27 a9 [2] 1a }

  condition:
    any of them
}