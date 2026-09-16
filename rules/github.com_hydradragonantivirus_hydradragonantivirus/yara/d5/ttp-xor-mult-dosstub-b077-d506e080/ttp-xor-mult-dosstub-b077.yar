rule TTP_XOR_MULT_DOSStub_b077 {
  strings:
    $key_b077 = { e4 1f [2] 90 07 [2] d7 05 [2] 90 14 [2] de 18 [2] d2 12 [2] c5 19 [2] de 57 [2] e3 }

  condition:
    any of them
}