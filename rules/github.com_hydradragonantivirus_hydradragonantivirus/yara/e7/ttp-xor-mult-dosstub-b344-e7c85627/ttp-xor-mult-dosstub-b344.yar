rule TTP_XOR_MULT_DOSStub_b344 {
  strings:
    $key_b344 = { e7 2c [2] 93 34 [2] d4 36 [2] 93 27 [2] dd 2b [2] d1 21 [2] c6 2a [2] dd 64 [2] e0 }

  condition:
    any of them
}