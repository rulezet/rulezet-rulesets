rule TTP_XOR_MULT_DOSStub_c8b1 {
  strings:
    $key_c8b1 = { 9c d9 [2] e8 c1 [2] af c3 [2] e8 d2 [2] a6 de [2] aa d4 [2] bd df [2] a6 91 [2] 9b }

  condition:
    any of them
}