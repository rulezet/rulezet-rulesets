rule TTP_XOR_MULT_DOSStub_3e81 {
  strings:
    $key_3e81 = { 6a e9 [2] 1e f1 [2] 59 f3 [2] 1e e2 [2] 50 ee [2] 5c e4 [2] 4b ef [2] 50 a1 [2] 6d }

  condition:
    any of them
}