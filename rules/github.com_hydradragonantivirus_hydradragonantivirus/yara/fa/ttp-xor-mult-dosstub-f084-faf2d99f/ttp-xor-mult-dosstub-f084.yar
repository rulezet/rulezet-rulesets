rule TTP_XOR_MULT_DOSStub_f084 {
  strings:
    $key_f084 = { a4 ec [2] d0 f4 [2] 97 f6 [2] d0 e7 [2] 9e eb [2] 92 e1 [2] 85 ea [2] 9e a4 [2] a3 }

  condition:
    any of them
}