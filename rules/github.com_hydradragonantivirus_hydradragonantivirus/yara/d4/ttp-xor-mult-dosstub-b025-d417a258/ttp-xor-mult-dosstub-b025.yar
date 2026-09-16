rule TTP_XOR_MULT_DOSStub_b025 {
  strings:
    $key_b025 = { e4 4d [2] 90 55 [2] d7 57 [2] 90 46 [2] de 4a [2] d2 40 [2] c5 4b [2] de 05 [2] e3 }

  condition:
    any of them
}