rule TTP_XOR_MULT_DOSStub_b0e4 {
  strings:
    $key_b0e4 = { e4 8c [2] 90 94 [2] d7 96 [2] 90 87 [2] de 8b [2] d2 81 [2] c5 8a [2] de c4 [2] e3 }

  condition:
    any of them
}