rule TTP_XOR_MULT_DOSStub_b071 {
  strings:
    $key_b071 = { e4 19 [2] 90 01 [2] d7 03 [2] 90 12 [2] de 1e [2] d2 14 [2] c5 1f [2] de 51 [2] e3 }

  condition:
    any of them
}