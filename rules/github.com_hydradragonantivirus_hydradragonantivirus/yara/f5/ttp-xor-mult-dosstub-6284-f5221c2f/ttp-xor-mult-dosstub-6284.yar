rule TTP_XOR_MULT_DOSStub_6284 {
  strings:
    $key_6284 = { 36 ec [2] 42 f4 [2] 05 f6 [2] 42 e7 [2] 0c eb [2] 00 e1 [2] 17 ea [2] 0c a4 [2] 31 }

  condition:
    any of them
}