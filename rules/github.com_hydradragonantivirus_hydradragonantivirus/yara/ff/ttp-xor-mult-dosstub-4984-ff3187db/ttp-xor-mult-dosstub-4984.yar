rule TTP_XOR_MULT_DOSStub_4984 {
  strings:
    $key_4984 = { 1d ec [2] 69 f4 [2] 2e f6 [2] 69 e7 [2] 27 eb [2] 2b e1 [2] 3c ea [2] 27 a4 [2] 1a }

  condition:
    any of them
}