rule TTP_XOR_MULT_DOSStub_4480 {
  strings:
    $key_4480 = { 10 e8 [2] 64 f0 [2] 23 f2 [2] 64 e3 [2] 2a ef [2] 26 e5 [2] 31 ee [2] 2a a0 [2] 17 }

  condition:
    any of them
}