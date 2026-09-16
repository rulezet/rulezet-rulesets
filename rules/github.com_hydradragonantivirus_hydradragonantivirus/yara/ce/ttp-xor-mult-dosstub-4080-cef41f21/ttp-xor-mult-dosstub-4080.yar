rule TTP_XOR_MULT_DOSStub_4080 {
  strings:
    $key_4080 = { 14 e8 [2] 60 f0 [2] 27 f2 [2] 60 e3 [2] 2e ef [2] 22 e5 [2] 35 ee [2] 2e a0 [2] 13 }

  condition:
    any of them
}