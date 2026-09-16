rule TTP_XOR_MULT_DOSStub_0680 {
  strings:
    $key_0680 = { 52 e8 [2] 26 f0 [2] 61 f2 [2] 26 e3 [2] 68 ef [2] 64 e5 [2] 73 ee [2] 68 a0 [2] 55 }

  condition:
    any of them
}