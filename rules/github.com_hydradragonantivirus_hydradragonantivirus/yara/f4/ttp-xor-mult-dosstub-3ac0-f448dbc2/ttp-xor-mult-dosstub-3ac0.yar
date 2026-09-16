rule TTP_XOR_MULT_DOSStub_3ac0 {
  strings:
    $key_3ac0 = { 6e a8 [2] 1a b0 [2] 5d b2 [2] 1a a3 [2] 54 af [2] 58 a5 [2] 4f ae [2] 54 e0 [2] 69 }

  condition:
    any of them
}