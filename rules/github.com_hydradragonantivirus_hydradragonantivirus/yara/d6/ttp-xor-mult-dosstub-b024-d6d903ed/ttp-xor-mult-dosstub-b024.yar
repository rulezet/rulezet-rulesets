rule TTP_XOR_MULT_DOSStub_b024 {
  strings:
    $key_b024 = { e4 4c [2] 90 54 [2] d7 56 [2] 90 47 [2] de 4b [2] d2 41 [2] c5 4a [2] de 04 [2] e3 }

  condition:
    any of them
}