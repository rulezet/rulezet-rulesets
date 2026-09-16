rule TTP_XOR_MULT_DOSStub_7981 {
  strings:
    $key_7981 = { 2d e9 [2] 59 f1 [2] 1e f3 [2] 59 e2 [2] 17 ee [2] 1b e4 [2] 0c ef [2] 17 a1 [2] 2a }

  condition:
    any of them
}