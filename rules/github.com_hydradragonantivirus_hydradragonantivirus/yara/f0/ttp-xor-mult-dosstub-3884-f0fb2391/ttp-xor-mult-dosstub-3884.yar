rule TTP_XOR_MULT_DOSStub_3884 {
  strings:
    $key_3884 = { 6c ec [2] 18 f4 [2] 5f f6 [2] 18 e7 [2] 56 eb [2] 5a e1 [2] 4d ea [2] 56 a4 [2] 6b }

  condition:
    any of them
}