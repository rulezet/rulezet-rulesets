rule TTP_XOR_MULT_DOSStub_2ed9 {
  strings:
    $key_2ed9 = { 7a b1 [2] 0e a9 [2] 49 ab [2] 0e ba [2] 40 b6 [2] 4c bc [2] 5b b7 [2] 40 f9 [2] 7d }

  condition:
    any of them
}