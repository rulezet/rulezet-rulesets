rule TTP_XOR_MULT_DOSStub_b02b {
  strings:
    $key_b02b = { e4 43 [2] 90 5b [2] d7 59 [2] 90 48 [2] de 44 [2] d2 4e [2] c5 45 [2] de 0b [2] e3 }

  condition:
    any of them
}