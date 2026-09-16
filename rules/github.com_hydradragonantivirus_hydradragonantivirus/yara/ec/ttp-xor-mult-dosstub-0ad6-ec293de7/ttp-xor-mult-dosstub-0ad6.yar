rule TTP_XOR_MULT_DOSStub_0ad6 {
  strings:
    $key_0ad6 = { 5e be [2] 2a a6 [2] 6d a4 [2] 2a b5 [2] 64 b9 [2] 68 b3 [2] 7f b8 [2] 64 f6 [2] 59 }

  condition:
    any of them
}