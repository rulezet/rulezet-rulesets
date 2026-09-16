rule TTP_XOR_MULT_DOSStub_1c84 {
  strings:
    $key_1c84 = { 48 ec [2] 3c f4 [2] 7b f6 [2] 3c e7 [2] 72 eb [2] 7e e1 [2] 69 ea [2] 72 a4 [2] 4f }

  condition:
    any of them
}