rule TTP_XOR_MULT_DOSStub_44c7 {
  strings:
    $key_44c7 = { 10 af [2] 64 b7 [2] 23 b5 [2] 64 a4 [2] 2a a8 [2] 26 a2 [2] 31 a9 [2] 2a e7 [2] 17 }

  condition:
    any of them
}