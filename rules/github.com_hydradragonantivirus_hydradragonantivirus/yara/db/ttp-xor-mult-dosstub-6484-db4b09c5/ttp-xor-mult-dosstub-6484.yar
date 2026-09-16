rule TTP_XOR_MULT_DOSStub_6484 {
  strings:
    $key_6484 = { 30 ec [2] 44 f4 [2] 03 f6 [2] 44 e7 [2] 0a eb [2] 06 e1 [2] 11 ea [2] 0a a4 [2] 37 }

  condition:
    any of them
}