rule TTP_XOR_MULT_DOSStub_1284 {
  strings:
    $key_1284 = { 46 ec [2] 32 f4 [2] 75 f6 [2] 32 e7 [2] 7c eb [2] 70 e1 [2] 67 ea [2] 7c a4 [2] 41 }

  condition:
    any of them
}