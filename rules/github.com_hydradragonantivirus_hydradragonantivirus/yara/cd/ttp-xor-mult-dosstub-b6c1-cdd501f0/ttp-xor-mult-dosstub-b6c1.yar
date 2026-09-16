rule TTP_XOR_MULT_DOSStub_b6c1 {
  strings:
    $key_b6c1 = { e2 a9 [2] 96 b1 [2] d1 b3 [2] 96 a2 [2] d8 ae [2] d4 a4 [2] c3 af [2] d8 e1 [2] e5 }

  condition:
    any of them
}