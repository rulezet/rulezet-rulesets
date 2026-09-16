rule TTP_XOR_MULT_DOSStub_b011 {
  strings:
    $key_b011 = { e4 79 [2] 90 61 [2] d7 63 [2] 90 72 [2] de 7e [2] d2 74 [2] c5 7f [2] de 31 [2] e3 }

  condition:
    any of them
}