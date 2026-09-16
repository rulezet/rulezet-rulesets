rule TTP_XOR_MULT_DOSStub_5ad6 {
  strings:
    $key_5ad6 = { 0e be [2] 7a a6 [2] 3d a4 [2] 7a b5 [2] 34 b9 [2] 38 b3 [2] 2f b8 [2] 34 f6 [2] 09 }

  condition:
    any of them
}