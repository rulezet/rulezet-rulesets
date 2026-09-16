rule TTP_XOR_MULT_DOSStub_b348 {
  strings:
    $key_b348 = { e7 20 [2] 93 38 [2] d4 3a [2] 93 2b [2] dd 27 [2] d1 2d [2] c6 26 [2] dd 68 [2] e0 }

  condition:
    any of them
}