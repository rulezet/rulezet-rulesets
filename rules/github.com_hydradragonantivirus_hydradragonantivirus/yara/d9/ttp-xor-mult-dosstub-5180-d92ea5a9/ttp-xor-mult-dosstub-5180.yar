rule TTP_XOR_MULT_DOSStub_5180 {
  strings:
    $key_5180 = { 05 e8 [2] 71 f0 [2] 36 f2 [2] 71 e3 [2] 3f ef [2] 33 e5 [2] 24 ee [2] 3f a0 [2] 02 }

  condition:
    any of them
}