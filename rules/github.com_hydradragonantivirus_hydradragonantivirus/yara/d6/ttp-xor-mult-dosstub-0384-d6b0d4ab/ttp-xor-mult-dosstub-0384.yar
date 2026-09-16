rule TTP_XOR_MULT_DOSStub_0384 {
  strings:
    $key_0384 = { 57 ec [2] 23 f4 [2] 64 f6 [2] 23 e7 [2] 6d eb [2] 61 e1 [2] 76 ea [2] 6d a4 [2] 50 }

  condition:
    any of them
}