rule TTP_XOR_MULT_DOSStub_7ec0 {
  strings:
    $key_7ec0 = { 2a a8 [2] 5e b0 [2] 19 b2 [2] 5e a3 [2] 10 af [2] 1c a5 [2] 0b ae [2] 10 e0 [2] 2d }

  condition:
    any of them
}