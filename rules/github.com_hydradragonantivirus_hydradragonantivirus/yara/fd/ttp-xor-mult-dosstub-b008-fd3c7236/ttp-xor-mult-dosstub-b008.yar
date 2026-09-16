rule TTP_XOR_MULT_DOSStub_b008 {
  strings:
    $key_b008 = { e4 60 [2] 90 78 [2] d7 7a [2] 90 6b [2] de 67 [2] d2 6d [2] c5 66 [2] de 28 [2] e3 }

  condition:
    any of them
}