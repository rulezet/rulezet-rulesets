rule TTP_XOR_MULT_DOSStub_1ac0 {
  strings:
    $key_1ac0 = { 4e a8 [2] 3a b0 [2] 7d b2 [2] 3a a3 [2] 74 af [2] 78 a5 [2] 6f ae [2] 74 e0 [2] 49 }

  condition:
    any of them
}