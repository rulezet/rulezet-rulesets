rule TTP_XOR_MULT_DOSStub_3680 {
  strings:
    $key_3680 = { 62 e8 [2] 16 f0 [2] 51 f2 [2] 16 e3 [2] 58 ef [2] 54 e5 [2] 43 ee [2] 58 a0 [2] 65 }

  condition:
    any of them
}