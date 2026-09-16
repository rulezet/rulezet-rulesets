rule TTP_XOR_MULT_DOSStub_b031 {
  strings:
    $key_b031 = { e4 59 [2] 90 41 [2] d7 43 [2] 90 52 [2] de 5e [2] d2 54 [2] c5 5f [2] de 11 [2] e3 }

  condition:
    any of them
}