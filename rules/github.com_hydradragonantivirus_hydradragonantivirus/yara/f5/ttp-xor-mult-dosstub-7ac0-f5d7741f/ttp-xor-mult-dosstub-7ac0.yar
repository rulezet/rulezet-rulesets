rule TTP_XOR_MULT_DOSStub_7ac0 {
  strings:
    $key_7ac0 = { 2e a8 [2] 5a b0 [2] 1d b2 [2] 5a a3 [2] 14 af [2] 18 a5 [2] 0f ae [2] 14 e0 [2] 29 }

  condition:
    any of them
}