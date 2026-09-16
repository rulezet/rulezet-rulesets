rule TTP_XOR_MULT_DOSStub_4486 {
  strings:
    $key_4486 = { 10 ee [2] 64 f6 [2] 23 f4 [2] 64 e5 [2] 2a e9 [2] 26 e3 [2] 31 e8 [2] 2a a6 [2] 17 }

  condition:
    any of them
}