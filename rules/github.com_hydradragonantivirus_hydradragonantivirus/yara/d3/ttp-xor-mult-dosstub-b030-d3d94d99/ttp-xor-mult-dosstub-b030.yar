rule TTP_XOR_MULT_DOSStub_b030 {
  strings:
    $key_b030 = { e4 58 [2] 90 40 [2] d7 42 [2] 90 53 [2] de 5f [2] d2 55 [2] c5 5e [2] de 10 [2] e3 }

  condition:
    any of them
}