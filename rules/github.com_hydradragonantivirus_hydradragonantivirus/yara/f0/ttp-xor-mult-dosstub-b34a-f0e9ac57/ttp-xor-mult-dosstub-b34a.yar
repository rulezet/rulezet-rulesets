rule TTP_XOR_MULT_DOSStub_b34a {
  strings:
    $key_b34a = { e7 22 [2] 93 3a [2] d4 38 [2] 93 29 [2] dd 25 [2] d1 2f [2] c6 24 [2] dd 6a [2] e0 }

  condition:
    any of them
}