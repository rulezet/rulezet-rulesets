rule TTP_XOR_MULT_DOSStub_7887 {
  strings:
    $key_7887 = { 2c ef [2] 58 f7 [2] 1f f5 [2] 58 e4 [2] 16 e8 [2] 1a e2 [2] 0d e9 [2] 16 a7 [2] 2b }

  condition:
    any of them
}