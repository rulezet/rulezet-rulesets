rule TTP_XOR_MULT_DOSStub_c087 {
  strings:
    $key_c087 = { 94 ef [2] e0 f7 [2] a7 f5 [2] e0 e4 [2] ae e8 [2] a2 e2 [2] b5 e9 [2] ae a7 [2] 93 }

  condition:
    any of them
}