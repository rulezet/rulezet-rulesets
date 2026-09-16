rule TTP_XOR_MULT_DOSStub_4381 {
  strings:
    $key_4381 = { 17 e9 [2] 63 f1 [2] 24 f3 [2] 63 e2 [2] 2d ee [2] 21 e4 [2] 36 ef [2] 2d a1 [2] 10 }

  condition:
    any of them
}