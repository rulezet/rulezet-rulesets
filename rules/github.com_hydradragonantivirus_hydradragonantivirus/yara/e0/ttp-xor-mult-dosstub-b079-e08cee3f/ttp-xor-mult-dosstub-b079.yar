rule TTP_XOR_MULT_DOSStub_b079 {
  strings:
    $key_b079 = { e4 11 [2] 90 09 [2] d7 0b [2] 90 1a [2] de 16 [2] d2 1c [2] c5 17 [2] de 59 [2] e3 }

  condition:
    any of them
}