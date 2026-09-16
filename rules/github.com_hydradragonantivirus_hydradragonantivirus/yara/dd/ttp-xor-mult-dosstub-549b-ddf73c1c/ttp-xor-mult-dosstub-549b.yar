rule TTP_XOR_MULT_DOSStub_549b {
  strings:
    $key_549b = { 00 f3 [2] 74 eb [2] 33 e9 [2] 74 f8 [2] 3a f4 [2] 36 fe [2] 21 f5 [2] 3a bb [2] 07 }

  condition:
    any of them
}