rule TTP_XOR_MULT_DOSStub_8a89 {
  strings:
    $key_8a89 = { de e1 [2] aa f9 [2] ed fb [2] aa ea [2] e4 e6 [2] e8 ec [2] ff e7 [2] e4 a9 [2] d9 }

  condition:
    any of them
}