rule TTP_XOR_MULT_DOSStub_0284 {
  strings:
    $key_0284 = { 56 ec [2] 22 f4 [2] 65 f6 [2] 22 e7 [2] 6c eb [2] 60 e1 [2] 77 ea [2] 6c a4 [2] 51 }

  condition:
    any of them
}