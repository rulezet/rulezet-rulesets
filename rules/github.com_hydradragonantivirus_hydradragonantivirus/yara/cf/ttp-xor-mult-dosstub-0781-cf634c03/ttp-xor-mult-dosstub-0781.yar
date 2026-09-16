rule TTP_XOR_MULT_DOSStub_0781 {
  strings:
    $key_0781 = { 53 e9 [2] 27 f1 [2] 60 f3 [2] 27 e2 [2] 69 ee [2] 65 e4 [2] 72 ef [2] 69 a1 [2] 54 }

  condition:
    any of them
}