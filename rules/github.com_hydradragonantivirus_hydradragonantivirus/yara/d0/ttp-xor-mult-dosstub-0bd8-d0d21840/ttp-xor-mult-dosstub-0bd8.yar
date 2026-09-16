rule TTP_XOR_MULT_DOSStub_0bd8 {
  strings:
    $key_0bd8 = { 5f b0 [2] 2b a8 [2] 6c aa [2] 2b bb [2] 65 b7 [2] 69 bd [2] 7e b6 [2] 65 f8 [2] 58 }

  condition:
    any of them
}