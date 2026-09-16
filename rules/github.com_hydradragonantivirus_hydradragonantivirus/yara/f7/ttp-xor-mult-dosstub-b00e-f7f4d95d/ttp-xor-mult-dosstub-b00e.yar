rule TTP_XOR_MULT_DOSStub_b00e {
  strings:
    $key_b00e = { e4 66 [2] 90 7e [2] d7 7c [2] 90 6d [2] de 61 [2] d2 6b [2] c5 60 [2] de 2e [2] e3 }

  condition:
    any of them
}