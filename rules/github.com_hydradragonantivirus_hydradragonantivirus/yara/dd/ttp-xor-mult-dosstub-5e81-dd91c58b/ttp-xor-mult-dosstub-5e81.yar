rule TTP_XOR_MULT_DOSStub_5e81 {
  strings:
    $key_5e81 = { 0a e9 [2] 7e f1 [2] 39 f3 [2] 7e e2 [2] 30 ee [2] 3c e4 [2] 2b ef [2] 30 a1 [2] 0d }

  condition:
    any of them
}