rule TTP_XOR_MULT_DOSStub_3381 {
  strings:
    $key_3381 = { 67 e9 [2] 13 f1 [2] 54 f3 [2] 13 e2 [2] 5d ee [2] 51 e4 [2] 46 ef [2] 5d a1 [2] 60 }

  condition:
    any of them
}