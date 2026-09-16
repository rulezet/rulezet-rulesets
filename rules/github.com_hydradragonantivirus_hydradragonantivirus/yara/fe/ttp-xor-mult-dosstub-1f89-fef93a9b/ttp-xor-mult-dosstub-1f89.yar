rule TTP_XOR_MULT_DOSStub_1f89 {
  strings:
    $key_1f89 = { 4b e1 [2] 3f f9 [2] 78 fb [2] 3f ea [2] 71 e6 [2] 7d ec [2] 6a e7 [2] 71 a9 [2] 4c }

  condition:
    any of them
}