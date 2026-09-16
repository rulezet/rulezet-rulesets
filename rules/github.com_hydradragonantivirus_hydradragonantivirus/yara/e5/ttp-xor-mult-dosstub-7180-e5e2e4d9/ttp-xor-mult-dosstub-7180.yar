rule TTP_XOR_MULT_DOSStub_7180 {
  strings:
    $key_7180 = { 25 e8 [2] 51 f0 [2] 16 f2 [2] 51 e3 [2] 1f ef [2] 13 e5 [2] 04 ee [2] 1f a0 [2] 22 }

  condition:
    any of them
}