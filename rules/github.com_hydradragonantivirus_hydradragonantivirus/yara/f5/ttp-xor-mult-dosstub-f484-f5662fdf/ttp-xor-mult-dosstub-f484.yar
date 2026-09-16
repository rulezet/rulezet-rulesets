rule TTP_XOR_MULT_DOSStub_f484 {
  strings:
    $key_f484 = { a0 ec [2] d4 f4 [2] 93 f6 [2] d4 e7 [2] 9a eb [2] 96 e1 [2] 81 ea [2] 9a a4 [2] a7 }

  condition:
    any of them
}