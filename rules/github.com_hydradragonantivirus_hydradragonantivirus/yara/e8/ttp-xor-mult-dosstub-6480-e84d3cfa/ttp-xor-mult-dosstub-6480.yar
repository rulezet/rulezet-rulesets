rule TTP_XOR_MULT_DOSStub_6480 {
  strings:
    $key_6480 = { 30 e8 [2] 44 f0 [2] 03 f2 [2] 44 e3 [2] 0a ef [2] 06 e5 [2] 11 ee [2] 0a a0 [2] 37 }

  condition:
    any of them
}