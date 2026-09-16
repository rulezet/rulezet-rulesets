rule TTP_XOR_MULT_DOSStub_0ec0 {
  strings:
    $key_0ec0 = { 5a a8 [2] 2e b0 [2] 69 b2 [2] 2e a3 [2] 60 af [2] 6c a5 [2] 7b ae [2] 60 e0 [2] 5d }

  condition:
    any of them
}