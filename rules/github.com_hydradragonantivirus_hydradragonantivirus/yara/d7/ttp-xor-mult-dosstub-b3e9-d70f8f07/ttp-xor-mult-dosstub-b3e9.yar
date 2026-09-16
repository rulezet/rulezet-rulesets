rule TTP_XOR_MULT_DOSStub_b3e9 {
  strings:
    $key_b3e9 = { e7 81 [2] 93 99 [2] d4 9b [2] 93 8a [2] dd 86 [2] d1 8c [2] c6 87 [2] dd c9 [2] e0 }

  condition:
    any of them
}