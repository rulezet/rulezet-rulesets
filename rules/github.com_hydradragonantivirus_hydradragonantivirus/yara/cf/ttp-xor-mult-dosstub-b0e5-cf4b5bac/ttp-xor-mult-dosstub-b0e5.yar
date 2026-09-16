rule TTP_XOR_MULT_DOSStub_b0e5 {
  strings:
    $key_b0e5 = { e4 8d [2] 90 95 [2] d7 97 [2] 90 86 [2] de 8a [2] d2 80 [2] c5 8b [2] de c5 [2] e3 }

  condition:
    any of them
}