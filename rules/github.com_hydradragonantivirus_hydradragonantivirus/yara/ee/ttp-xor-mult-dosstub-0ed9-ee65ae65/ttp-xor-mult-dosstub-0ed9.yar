rule TTP_XOR_MULT_DOSStub_0ed9 {
  strings:
    $key_0ed9 = { 5a b1 [2] 2e a9 [2] 69 ab [2] 2e ba [2] 60 b6 [2] 6c bc [2] 7b b7 [2] 60 f9 [2] 5d }

  condition:
    any of them
}