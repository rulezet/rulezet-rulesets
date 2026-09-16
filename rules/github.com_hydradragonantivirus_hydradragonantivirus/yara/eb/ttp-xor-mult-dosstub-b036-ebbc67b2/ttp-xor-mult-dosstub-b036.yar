rule TTP_XOR_MULT_DOSStub_b036 {
  strings:
    $key_b036 = { e4 5e [2] 90 46 [2] d7 44 [2] 90 55 [2] de 59 [2] d2 53 [2] c5 58 [2] de 16 [2] e3 }

  condition:
    any of them
}