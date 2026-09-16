rule TTP_XOR_MULT_DOSStub_3487 {
  strings:
    $key_3487 = { 60 ef [2] 14 f7 [2] 53 f5 [2] 14 e4 [2] 5a e8 [2] 56 e2 [2] 41 e9 [2] 5a a7 [2] 67 }

  condition:
    any of them
}