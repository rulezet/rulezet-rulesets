rule TTP_XOR_MULT_DOSStub_b006 {
  strings:
    $key_b006 = { e4 6e [2] 90 76 [2] d7 74 [2] 90 65 [2] de 69 [2] d2 63 [2] c5 68 [2] de 26 [2] e3 }

  condition:
    any of them
}