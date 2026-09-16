rule TTP_XOR_MULT_DOSStub_5080 {
  strings:
    $key_5080 = { 04 e8 [2] 70 f0 [2] 37 f2 [2] 70 e3 [2] 3e ef [2] 32 e5 [2] 25 ee [2] 3e a0 [2] 03 }

  condition:
    any of them
}