rule TTP_XOR_MULT_DOSStub_b041 {
  strings:
    $key_b041 = { e4 29 [2] 90 31 [2] d7 33 [2] 90 22 [2] de 2e [2] d2 24 [2] c5 2f [2] de 61 [2] e3 }

  condition:
    any of them
}