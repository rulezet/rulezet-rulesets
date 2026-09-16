rule TTP_XOR_MULT_DOSStub_2584 {
  strings:
    $key_2584 = { 71 ec [2] 05 f4 [2] 42 f6 [2] 05 e7 [2] 4b eb [2] 47 e1 [2] 50 ea [2] 4b a4 [2] 76 }

  condition:
    any of them
}