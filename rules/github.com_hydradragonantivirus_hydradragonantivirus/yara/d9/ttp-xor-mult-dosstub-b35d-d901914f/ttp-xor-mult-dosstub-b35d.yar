rule TTP_XOR_MULT_DOSStub_b35d {
  strings:
    $key_b35d = { e7 35 [2] 93 2d [2] d4 2f [2] 93 3e [2] dd 32 [2] d1 38 [2] c6 33 [2] dd 7d [2] e0 }

  condition:
    any of them
}