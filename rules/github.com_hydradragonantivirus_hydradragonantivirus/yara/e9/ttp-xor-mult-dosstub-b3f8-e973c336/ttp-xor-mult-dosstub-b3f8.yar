rule TTP_XOR_MULT_DOSStub_b3f8 {
  strings:
    $key_b3f8 = { e7 90 [2] 93 88 [2] d4 8a [2] 93 9b [2] dd 97 [2] d1 9d [2] c6 96 [2] dd d8 [2] e0 }

  condition:
    any of them
}