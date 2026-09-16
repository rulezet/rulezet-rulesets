rule TTP_XOR_MULT_DOSStub_1780 {
  strings:
    $key_1780 = { 43 e8 [2] 37 f0 [2] 70 f2 [2] 37 e3 [2] 79 ef [2] 75 e5 [2] 62 ee [2] 79 a0 [2] 44 }

  condition:
    any of them
}