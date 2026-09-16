rule TTP_XOR_MULT_DOSStub_b017 {
  strings:
    $key_b017 = { e4 7f [2] 90 67 [2] d7 65 [2] 90 74 [2] de 78 [2] d2 72 [2] c5 79 [2] de 37 [2] e3 }

  condition:
    any of them
}