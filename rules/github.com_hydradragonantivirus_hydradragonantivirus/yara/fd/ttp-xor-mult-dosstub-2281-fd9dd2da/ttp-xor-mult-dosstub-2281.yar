rule TTP_XOR_MULT_DOSStub_2281 {
  strings:
    $key_2281 = { 76 e9 [2] 02 f1 [2] 45 f3 [2] 02 e2 [2] 4c ee [2] 40 e4 [2] 57 ef [2] 4c a1 [2] 71 }

  condition:
    any of them
}