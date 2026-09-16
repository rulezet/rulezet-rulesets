rule TTP_XOR_MULT_DOSStub_b058 {
  strings:
    $key_b058 = { e4 30 [2] 90 28 [2] d7 2a [2] 90 3b [2] de 37 [2] d2 3d [2] c5 36 [2] de 78 [2] e3 }

  condition:
    any of them
}