rule TTP_XOR_MULT_DOSStub_6180 {
  strings:
    $key_6180 = { 35 e8 [2] 41 f0 [2] 06 f2 [2] 41 e3 [2] 0f ef [2] 03 e5 [2] 14 ee [2] 0f a0 [2] 32 }

  condition:
    any of them
}