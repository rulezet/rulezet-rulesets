rule TTP_XOR_MULT_DOSStub_c8c1 {
  strings:
    $key_c8c1 = { 9c a9 [2] e8 b1 [2] af b3 [2] e8 a2 [2] a6 ae [2] aa a4 [2] bd af [2] a6 e1 [2] 9b }

  condition:
    any of them
}