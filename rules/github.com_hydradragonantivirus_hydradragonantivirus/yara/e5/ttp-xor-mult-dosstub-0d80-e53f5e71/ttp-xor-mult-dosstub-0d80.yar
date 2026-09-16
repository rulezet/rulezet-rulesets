rule TTP_XOR_MULT_DOSStub_0d80 {
  strings:
    $key_0d80 = { 59 e8 [2] 2d f0 [2] 6a f2 [2] 2d e3 [2] 63 ef [2] 6f e5 [2] 78 ee [2] 63 a0 [2] 5e }

  condition:
    any of them
}