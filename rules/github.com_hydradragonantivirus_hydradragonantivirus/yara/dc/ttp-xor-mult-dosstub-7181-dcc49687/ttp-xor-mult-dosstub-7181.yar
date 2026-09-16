rule TTP_XOR_MULT_DOSStub_7181 {
  strings:
    $key_7181 = { 25 e9 [2] 51 f1 [2] 16 f3 [2] 51 e2 [2] 1f ee [2] 13 e4 [2] 04 ef [2] 1f a1 [2] 22 }

  condition:
    any of them
}