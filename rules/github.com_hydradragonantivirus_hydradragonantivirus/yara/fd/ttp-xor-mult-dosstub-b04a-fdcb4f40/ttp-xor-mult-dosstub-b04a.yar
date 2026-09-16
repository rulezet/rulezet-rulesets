rule TTP_XOR_MULT_DOSStub_b04a {
  strings:
    $key_b04a = { e4 22 [2] 90 3a [2] d7 38 [2] 90 29 [2] de 25 [2] d2 2f [2] c5 24 [2] de 6a [2] e3 }

  condition:
    any of them
}