rule TTP_XOR_MULT_DOSStub_5ad5 {
  strings:
    $key_5ad5 = { 0e bd [2] 7a a5 [2] 3d a7 [2] 7a b6 [2] 34 ba [2] 38 b0 [2] 2f bb [2] 34 f5 [2] 09 }

  condition:
    any of them
}