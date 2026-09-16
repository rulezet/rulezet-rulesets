rule TTP_XOR_MULT_DOSStub_b676 {
  strings:
    $key_b676 = { e2 1e [2] 96 06 [2] d1 04 [2] 96 15 [2] d8 19 [2] d4 13 [2] c3 18 [2] d8 56 [2] e5 }

  condition:
    any of them
}