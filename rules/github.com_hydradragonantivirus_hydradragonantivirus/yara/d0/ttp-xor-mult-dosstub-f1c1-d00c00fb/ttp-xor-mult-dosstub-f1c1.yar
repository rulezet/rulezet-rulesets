rule TTP_XOR_MULT_DOSStub_f1c1 {
  strings:
    $key_f1c1 = { a5 a9 [2] d1 b1 [2] 96 b3 [2] d1 a2 [2] 9f ae [2] 93 a4 [2] 84 af [2] 9f e1 [2] a2 }

  condition:
    any of them
}