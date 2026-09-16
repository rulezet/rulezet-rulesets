rule TTP_XOR_MULT_DOSStub_b020 {
  strings:
    $key_b020 = { e4 48 [2] 90 50 [2] d7 52 [2] 90 43 [2] de 4f [2] d2 45 [2] c5 4e [2] de 00 [2] e3 }

  condition:
    any of them
}