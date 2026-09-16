rule TTP_XOR_MULT_DOSStub_b6d6 {
  strings:
    $key_b6d6 = { e2 be [2] 96 a6 [2] d1 a4 [2] 96 b5 [2] d8 b9 [2] d4 b3 [2] c3 b8 [2] d8 f6 [2] e5 }

  condition:
    any of them
}