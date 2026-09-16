rule TTP_XOR_MULT_DOSStub_b05b {
  strings:
    $key_b05b = { e4 33 [2] 90 2b [2] d7 29 [2] 90 38 [2] de 34 [2] d2 3e [2] c5 35 [2] de 7b [2] e3 }

  condition:
    any of them
}