rule TTP_XOR_MULT_DOSStub_b0fa {
  strings:
    $key_b0fa = { e4 92 [2] 90 8a [2] d7 88 [2] 90 99 [2] de 95 [2] d2 9f [2] c5 94 [2] de da [2] e3 }

  condition:
    any of them
}