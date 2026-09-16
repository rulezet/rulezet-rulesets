rule TTP_XOR_MULT_DOSStub_f584 {
  strings:
    $key_f584 = { a1 ec [2] d5 f4 [2] 92 f6 [2] d5 e7 [2] 9b eb [2] 97 e1 [2] 80 ea [2] 9b a4 [2] a6 }

  condition:
    any of them
}