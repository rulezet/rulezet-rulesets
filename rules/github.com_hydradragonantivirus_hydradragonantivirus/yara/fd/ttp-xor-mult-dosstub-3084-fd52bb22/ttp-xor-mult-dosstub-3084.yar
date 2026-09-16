rule TTP_XOR_MULT_DOSStub_3084 {
  strings:
    $key_3084 = { 64 ec [2] 10 f4 [2] 57 f6 [2] 10 e7 [2] 5e eb [2] 52 e1 [2] 45 ea [2] 5e a4 [2] 63 }

  condition:
    any of them
}