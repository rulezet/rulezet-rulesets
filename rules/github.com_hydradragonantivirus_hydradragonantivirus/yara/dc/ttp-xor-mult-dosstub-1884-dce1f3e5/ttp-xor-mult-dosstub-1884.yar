rule TTP_XOR_MULT_DOSStub_1884 {
  strings:
    $key_1884 = { 4c ec [2] 38 f4 [2] 7f f6 [2] 38 e7 [2] 76 eb [2] 7a e1 [2] 6d ea [2] 76 a4 [2] 4b }

  condition:
    any of them
}