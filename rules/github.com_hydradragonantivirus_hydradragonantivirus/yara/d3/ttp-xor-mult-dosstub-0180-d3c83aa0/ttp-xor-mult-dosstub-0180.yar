rule TTP_XOR_MULT_DOSStub_0180 {
  strings:
    $key_0180 = { 55 e8 [2] 21 f0 [2] 66 f2 [2] 21 e3 [2] 6f ef [2] 63 e5 [2] 74 ee [2] 6f a0 [2] 52 }

  condition:
    any of them
}