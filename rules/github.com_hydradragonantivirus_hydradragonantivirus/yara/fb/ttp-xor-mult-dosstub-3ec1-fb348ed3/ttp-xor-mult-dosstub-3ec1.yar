rule TTP_XOR_MULT_DOSStub_3ec1 {
  strings:
    $key_3ec1 = { 6a a9 [2] 1e b1 [2] 59 b3 [2] 1e a2 [2] 50 ae [2] 5c a4 [2] 4b af [2] 50 e1 [2] 6d }

  condition:
    any of them
}