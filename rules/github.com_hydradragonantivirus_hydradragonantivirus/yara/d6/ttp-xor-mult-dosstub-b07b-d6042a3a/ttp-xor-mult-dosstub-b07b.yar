rule TTP_XOR_MULT_DOSStub_b07b {
  strings:
    $key_b07b = { e4 13 [2] 90 0b [2] d7 09 [2] 90 18 [2] de 14 [2] d2 1e [2] c5 15 [2] de 5b [2] e3 }

  condition:
    any of them
}