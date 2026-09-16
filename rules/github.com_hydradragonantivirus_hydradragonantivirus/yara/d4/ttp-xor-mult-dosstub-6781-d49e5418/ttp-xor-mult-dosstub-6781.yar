rule TTP_XOR_MULT_DOSStub_6781 {
  strings:
    $key_6781 = { 33 e9 [2] 47 f1 [2] 00 f3 [2] 47 e2 [2] 09 ee [2] 05 e4 [2] 12 ef [2] 09 a1 [2] 34 }

  condition:
    any of them
}