rule TTP_XOR_MULT_DOSStub_b3f6 {
  strings:
    $key_b3f6 = { e7 9e [2] 93 86 [2] d4 84 [2] 93 95 [2] dd 99 [2] d1 93 [2] c6 98 [2] dd d6 [2] e0 }

  condition:
    any of them
}