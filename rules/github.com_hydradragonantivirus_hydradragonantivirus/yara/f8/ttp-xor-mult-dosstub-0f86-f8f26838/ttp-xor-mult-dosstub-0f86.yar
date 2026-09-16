rule TTP_XOR_MULT_DOSStub_0f86 {
  strings:
    $key_0f86 = { 5b ee [2] 2f f6 [2] 68 f4 [2] 2f e5 [2] 61 e9 [2] 6d e3 [2] 7a e8 [2] 61 a6 [2] 5c }

  condition:
    any of them
}