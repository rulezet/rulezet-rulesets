rule TTP_XOR_MULT_DOSStub_7084 {
  strings:
    $key_7084 = { 24 ec [2] 50 f4 [2] 17 f6 [2] 50 e7 [2] 1e eb [2] 12 e1 [2] 05 ea [2] 1e a4 [2] 23 }

  condition:
    any of them
}