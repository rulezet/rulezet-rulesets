rule TTP_XOR_MULT_DOSStub_ba87 {
  strings:
    $key_ba87 = { ee ef [2] 9a f7 [2] dd f5 [2] 9a e4 [2] d4 e8 [2] d8 e2 [2] cf e9 [2] d4 a7 [2] e9 }

  condition:
    any of them
}