rule TTP_XOR_MULT_DOSStub_5181 {
  strings:
    $key_5181 = { 05 e9 [2] 71 f1 [2] 36 f3 [2] 71 e2 [2] 3f ee [2] 33 e4 [2] 24 ef [2] 3f a1 [2] 02 }

  condition:
    any of them
}