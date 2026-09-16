rule TTP_XOR_MULT_DOSStub_b332 {
  strings:
    $key_b332 = { e7 5a [2] 93 42 [2] d4 40 [2] 93 51 [2] dd 5d [2] d1 57 [2] c6 5c [2] dd 12 [2] e0 }

  condition:
    any of them
}