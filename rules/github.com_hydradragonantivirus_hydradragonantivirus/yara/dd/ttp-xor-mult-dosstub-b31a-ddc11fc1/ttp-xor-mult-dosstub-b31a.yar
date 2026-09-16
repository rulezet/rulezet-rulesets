rule TTP_XOR_MULT_DOSStub_b31a {
  strings:
    $key_b31a = { e7 72 [2] 93 6a [2] d4 68 [2] 93 79 [2] dd 75 [2] d1 7f [2] c6 74 [2] dd 3a [2] e0 }

  condition:
    any of them
}