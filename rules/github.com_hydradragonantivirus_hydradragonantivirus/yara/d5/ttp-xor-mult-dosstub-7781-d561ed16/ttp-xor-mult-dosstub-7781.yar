rule TTP_XOR_MULT_DOSStub_7781 {
  strings:
    $key_7781 = { 23 e9 [2] 57 f1 [2] 10 f3 [2] 57 e2 [2] 19 ee [2] 15 e4 [2] 02 ef [2] 19 a1 [2] 24 }

  condition:
    any of them
}