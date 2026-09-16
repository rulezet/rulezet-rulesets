rule TTP_XOR_MULT_DOSStub_6f8b {
  strings:
    $key_6f8b = { 3b e3 [2] 4f fb [2] 08 f9 [2] 4f e8 [2] 01 e4 [2] 0d ee [2] 1a e5 [2] 01 ab [2] 3c }

  condition:
    any of them
}