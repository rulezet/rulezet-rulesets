rule TTP_XOR_MULT_DOSStub_4084 {
  strings:
    $key_4084 = { 14 ec [2] 60 f4 [2] 27 f6 [2] 60 e7 [2] 2e eb [2] 22 e1 [2] 35 ea [2] 2e a4 [2] 13 }

  condition:
    any of them
}