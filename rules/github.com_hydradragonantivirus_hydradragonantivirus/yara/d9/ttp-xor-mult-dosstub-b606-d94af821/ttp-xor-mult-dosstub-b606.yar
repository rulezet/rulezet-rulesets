rule TTP_XOR_MULT_DOSStub_b606 {
  strings:
    $key_b606 = { e2 6e [2] 96 76 [2] d1 74 [2] 96 65 [2] d8 69 [2] d4 63 [2] c3 68 [2] d8 26 [2] e5 }

  condition:
    any of them
}