rule TTP_XOR_MULT_DOSStub_b430 {
  strings:
    $key_b430 = { e0 58 [2] 94 40 [2] d3 42 [2] 94 53 [2] da 5f [2] d6 55 [2] c1 5e [2] da 10 [2] e7 }

  condition:
    any of them
}