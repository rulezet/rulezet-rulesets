rule TTP_XOR_MULT_DOSStub_3a89 {
  strings:
    $key_3a89 = { 6e e1 [2] 1a f9 [2] 5d fb [2] 1a ea [2] 54 e6 [2] 58 ec [2] 4f e7 [2] 54 a9 [2] 69 }

  condition:
    any of them
}