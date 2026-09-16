rule TTP_XOR_MULT_DOSStub_b3f2 {
  strings:
    $key_b3f2 = { e7 9a [2] 93 82 [2] d4 80 [2] 93 91 [2] dd 9d [2] d1 97 [2] c6 9c [2] dd d2 [2] e0 }

  condition:
    any of them
}