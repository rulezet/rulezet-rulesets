rule TTP_XOR_MULT_DOSStub_8ac0 {
  strings:
    $key_8ac0 = { de a8 [2] aa b0 [2] ed b2 [2] aa a3 [2] e4 af [2] e8 a5 [2] ff ae [2] e4 e0 [2] d9 }

  condition:
    any of them
}