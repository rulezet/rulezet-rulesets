rule TTP_XOR_MULT_DOSStub_b027 {
  strings:
    $key_b027 = { e4 4f [2] 90 57 [2] d7 55 [2] 90 44 [2] de 48 [2] d2 42 [2] c5 49 [2] de 07 [2] e3 }

  condition:
    any of them
}