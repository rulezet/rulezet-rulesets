rule TTP_XOR_MULT_DOSStub_b30a {
  strings:
    $key_b30a = { e7 62 [2] 93 7a [2] d4 78 [2] 93 69 [2] dd 65 [2] d1 6f [2] c6 64 [2] dd 2a [2] e0 }

  condition:
    any of them
}