rule TTP_XOR_MULT_DOSStub_b7d9 {
  strings:
    $key_b7d9 = { e3 b1 [2] 97 a9 [2] d0 ab [2] 97 ba [2] d9 b6 [2] d5 bc [2] c2 b7 [2] d9 f9 [2] e4 }

  condition:
    any of them
}