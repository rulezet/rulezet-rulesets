rule TTP_XOR_MULT_DOSStub_18c1 {
  strings:
    $key_18c1 = { 4c a9 [2] 38 b1 [2] 7f b3 [2] 38 a2 [2] 76 ae [2] 7a a4 [2] 6d af [2] 76 e1 [2] 4b }

  condition:
    any of them
}