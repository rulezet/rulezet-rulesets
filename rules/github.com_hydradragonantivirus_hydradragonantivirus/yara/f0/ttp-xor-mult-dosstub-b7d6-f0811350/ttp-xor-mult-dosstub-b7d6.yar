rule TTP_XOR_MULT_DOSStub_b7d6 {
  strings:
    $key_b7d6 = { e3 be [2] 97 a6 [2] d0 a4 [2] 97 b5 [2] d9 b9 [2] d5 b3 [2] c2 b8 [2] d9 f6 [2] e4 }

  condition:
    any of them
}