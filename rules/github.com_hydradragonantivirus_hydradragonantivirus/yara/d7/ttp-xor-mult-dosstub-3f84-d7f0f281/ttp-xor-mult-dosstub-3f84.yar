rule TTP_XOR_MULT_DOSStub_3f84 {
  strings:
    $key_3f84 = { 6b ec [2] 1f f4 [2] 58 f6 [2] 1f e7 [2] 51 eb [2] 5d e1 [2] 4a ea [2] 51 a4 [2] 6c }

  condition:
    any of them
}