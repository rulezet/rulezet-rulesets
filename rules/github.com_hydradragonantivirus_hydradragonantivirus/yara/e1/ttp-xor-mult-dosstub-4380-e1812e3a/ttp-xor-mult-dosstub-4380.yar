rule TTP_XOR_MULT_DOSStub_4380 {
  strings:
    $key_4380 = { 17 e8 [2] 63 f0 [2] 24 f2 [2] 63 e3 [2] 2d ef [2] 21 e5 [2] 36 ee [2] 2d a0 [2] 10 }

  condition:
    any of them
}