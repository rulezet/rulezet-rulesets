rule TTP_XOR_MULT_DOSStub_b789 {
  strings:
    $key_b789 = { e3 e1 [2] 97 f9 [2] d0 fb [2] 97 ea [2] d9 e6 [2] d5 ec [2] c2 e7 [2] d9 a9 [2] e4 }

  condition:
    any of them
}