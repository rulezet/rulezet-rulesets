rule TTP_XOR_MULT_DOSStub_2681 {
  strings:
    $key_2681 = { 72 e9 [2] 06 f1 [2] 41 f3 [2] 06 e2 [2] 48 ee [2] 44 e4 [2] 53 ef [2] 48 a1 [2] 75 }

  condition:
    any of them
}