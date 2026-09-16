rule TTP_XOR_MULT_DOSStub_3c84 {
  strings:
    $key_3c84 = { 68 ec [2] 1c f4 [2] 5b f6 [2] 1c e7 [2] 52 eb [2] 5e e1 [2] 49 ea [2] 52 a4 [2] 6f }

  condition:
    any of them
}