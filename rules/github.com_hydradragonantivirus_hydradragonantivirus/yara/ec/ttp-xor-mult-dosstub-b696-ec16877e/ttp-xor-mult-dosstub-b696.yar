rule TTP_XOR_MULT_DOSStub_b696 {
  strings:
    $key_b696 = { e2 fe [2] 96 e6 [2] d1 e4 [2] 96 f5 [2] d8 f9 [2] d4 f3 [2] c3 f8 [2] d8 b6 [2] e5 }

  condition:
    any of them
}