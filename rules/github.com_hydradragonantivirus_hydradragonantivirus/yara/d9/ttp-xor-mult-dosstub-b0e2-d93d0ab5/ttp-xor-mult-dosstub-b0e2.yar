rule TTP_XOR_MULT_DOSStub_b0e2 {
  strings:
    $key_b0e2 = { e4 8a [2] 90 92 [2] d7 90 [2] 90 81 [2] de 8d [2] d2 87 [2] c5 8c [2] de c2 [2] e3 }

  condition:
    any of them
}