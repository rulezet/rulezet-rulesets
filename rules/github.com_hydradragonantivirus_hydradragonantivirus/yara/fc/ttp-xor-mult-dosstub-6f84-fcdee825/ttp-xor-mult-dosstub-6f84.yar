rule TTP_XOR_MULT_DOSStub_6f84 {
  strings:
    $key_6f84 = { 3b ec [2] 4f f4 [2] 08 f6 [2] 4f e7 [2] 01 eb [2] 0d e1 [2] 1a ea [2] 01 a4 [2] 3c }

  condition:
    any of them
}