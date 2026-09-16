rule TTP_XOR_MULT_DOSStub_dc89 {
  strings:
    $key_dc89 = { 88 e1 [2] fc f9 [2] bb fb [2] fc ea [2] b2 e6 [2] be ec [2] a9 e7 [2] b2 a9 [2] 8f }

  condition:
    any of them
}