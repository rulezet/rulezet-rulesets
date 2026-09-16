rule TTP_XOR_MULT_DOSStub_b6d0 {
  strings:
    $key_b6d0 = { e2 b8 [2] 96 a0 [2] d1 a2 [2] 96 b3 [2] d8 bf [2] d4 b5 [2] c3 be [2] d8 f0 [2] e5 }

  condition:
    any of them
}