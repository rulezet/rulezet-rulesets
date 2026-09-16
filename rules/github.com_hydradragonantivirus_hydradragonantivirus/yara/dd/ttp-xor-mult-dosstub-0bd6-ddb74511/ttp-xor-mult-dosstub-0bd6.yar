rule TTP_XOR_MULT_DOSStub_0bd6 {
  strings:
    $key_0bd6 = { 5f be [2] 2b a6 [2] 6c a4 [2] 2b b5 [2] 65 b9 [2] 69 b3 [2] 7e b8 [2] 65 f6 [2] 58 }

  condition:
    any of them
}