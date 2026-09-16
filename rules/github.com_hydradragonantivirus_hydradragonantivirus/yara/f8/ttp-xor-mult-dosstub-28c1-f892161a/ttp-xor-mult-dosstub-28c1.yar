rule TTP_XOR_MULT_DOSStub_28c1 {
  strings:
    $key_28c1 = { 7c a9 [2] 08 b1 [2] 4f b3 [2] 08 a2 [2] 46 ae [2] 4a a4 [2] 5d af [2] 46 e1 [2] 7b }

  condition:
    any of them
}