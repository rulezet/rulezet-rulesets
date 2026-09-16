rule TTP_XOR_MULT_DOSStub_0989 {
  strings:
    $key_0989 = { 5d e1 [2] 29 f9 [2] 6e fb [2] 29 ea [2] 67 e6 [2] 6b ec [2] 7c e7 [2] 67 a9 [2] 5a }

  condition:
    any of them
}