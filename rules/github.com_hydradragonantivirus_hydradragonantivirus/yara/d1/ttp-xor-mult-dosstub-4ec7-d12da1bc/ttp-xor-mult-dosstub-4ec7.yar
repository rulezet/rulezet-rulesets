rule TTP_XOR_MULT_DOSStub_4ec7 {
  strings:
    $key_4ec7 = { 1a af [2] 6e b7 [2] 29 b5 [2] 6e a4 [2] 20 a8 [2] 2c a2 [2] 3b a9 [2] 20 e7 [2] 1d }

  condition:
    any of them
}