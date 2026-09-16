rule TTP_XOR_MULT_DOSStub_7880 {
  strings:
    $key_7880 = { 2c e8 [2] 58 f0 [2] 1f f2 [2] 58 e3 [2] 16 ef [2] 1a e5 [2] 0d ee [2] 16 a0 [2] 2b }

  condition:
    any of them
}