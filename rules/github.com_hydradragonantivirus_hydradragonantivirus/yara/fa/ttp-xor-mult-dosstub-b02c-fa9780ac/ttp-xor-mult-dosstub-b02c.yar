rule TTP_XOR_MULT_DOSStub_b02c {
  strings:
    $key_b02c = { e4 44 [2] 90 5c [2] d7 5e [2] 90 4f [2] de 43 [2] d2 49 [2] c5 42 [2] de 0c [2] e3 }

  condition:
    any of them
}