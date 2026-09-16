rule TTP_XOR_MULT_DOSStub_0d87 {
  strings:
    $key_0d87 = { 59 ef [2] 2d f7 [2] 6a f5 [2] 2d e4 [2] 63 e8 [2] 6f e2 [2] 78 e9 [2] 63 a7 [2] 5e }

  condition:
    any of them
}