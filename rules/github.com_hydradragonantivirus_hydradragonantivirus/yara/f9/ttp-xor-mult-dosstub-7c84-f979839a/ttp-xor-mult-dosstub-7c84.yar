rule TTP_XOR_MULT_DOSStub_7c84 {
  strings:
    $key_7c84 = { 28 ec [2] 5c f4 [2] 1b f6 [2] 5c e7 [2] 12 eb [2] 1e e1 [2] 09 ea [2] 12 a4 [2] 2f }

  condition:
    any of them
}