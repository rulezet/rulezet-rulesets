rule TTP_XOR_MULT_DOSStub_6f89 {
  strings:
    $key_6f89 = { 3b e1 [2] 4f f9 [2] 08 fb [2] 4f ea [2] 01 e6 [2] 0d ec [2] 1a e7 [2] 01 a9 [2] 3c }

  condition:
    any of them
}