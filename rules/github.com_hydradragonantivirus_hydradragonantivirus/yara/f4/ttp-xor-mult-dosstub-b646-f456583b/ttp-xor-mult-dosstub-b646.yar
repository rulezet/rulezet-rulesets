rule TTP_XOR_MULT_DOSStub_b646 {
  strings:
    $key_b646 = { e2 2e [2] 96 36 [2] d1 34 [2] 96 25 [2] d8 29 [2] d4 23 [2] c3 28 [2] d8 66 [2] e5 }

  condition:
    any of them
}