rule TTP_XOR_MULT_DOSStub_b687 {
  strings:
    $key_b687 = { e2 ef [2] 96 f7 [2] d1 f5 [2] 96 e4 [2] d8 e8 [2] d4 e2 [2] c3 e9 [2] d8 a7 [2] e5 }

  condition:
    any of them
}