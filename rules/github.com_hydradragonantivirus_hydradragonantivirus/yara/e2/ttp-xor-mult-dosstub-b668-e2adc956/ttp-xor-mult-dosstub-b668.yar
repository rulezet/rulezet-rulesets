rule TTP_XOR_MULT_DOSStub_b668 {
  strings:
    $key_b668 = { e2 00 [2] 96 18 [2] d1 1a [2] 96 0b [2] d8 07 [2] d4 0d [2] c3 06 [2] d8 48 [2] e5 }

  condition:
    any of them
}