rule TTP_XOR_MULT_DOSStub_5ad8 {
  strings:
    $key_5ad8 = { 0e b0 [2] 7a a8 [2] 3d aa [2] 7a bb [2] 34 b7 [2] 38 bd [2] 2f b6 [2] 34 f8 [2] 09 }

  condition:
    any of them
}