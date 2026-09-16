rule TTP_XOR_MULT_DOSStub_0e81 {
  strings:
    $key_0e81 = { 5a e9 [2] 2e f1 [2] 69 f3 [2] 2e e2 [2] 60 ee [2] 6c e4 [2] 7b ef [2] 60 a1 [2] 5d }

  condition:
    any of them
}