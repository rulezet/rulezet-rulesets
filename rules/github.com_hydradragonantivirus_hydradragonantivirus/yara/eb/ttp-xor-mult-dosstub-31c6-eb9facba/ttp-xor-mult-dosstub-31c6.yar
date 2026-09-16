rule TTP_XOR_MULT_DOSStub_31c6 {
  strings:
    $key_31c6 = { 65 ae [2] 11 b6 [2] 56 b4 [2] 11 a5 [2] 5f a9 [2] 53 a3 [2] 44 a8 [2] 5f e6 [2] 62 }

  condition:
    any of them
}