rule TTP_XOR_MULT_DOSStub_1e81 {
  strings:
    $key_1e81 = { 4a e9 [2] 3e f1 [2] 79 f3 [2] 3e e2 [2] 70 ee [2] 7c e4 [2] 6b ef [2] 70 a1 [2] 4d }

  condition:
    any of them
}