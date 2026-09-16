rule TTP_XOR_MULT_DOSStub_b365 {
  strings:
    $key_b365 = { e7 0d [2] 93 15 [2] d4 17 [2] 93 06 [2] dd 0a [2] d1 00 [2] c6 0b [2] dd 45 [2] e0 }

  condition:
    any of them
}