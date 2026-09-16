rule TTP_XOR_MULT_DOSStub_1187 {
  strings:
    $key_1187 = { 45 ef [2] 31 f7 [2] 76 f5 [2] 31 e4 [2] 7f e8 [2] 73 e2 [2] 64 e9 [2] 7f a7 [2] 42 }

  condition:
    any of them
}