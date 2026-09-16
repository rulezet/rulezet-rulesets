rule TTP_XOR_MULT_DOSStub_b768 {
  strings:
    $key_b768 = { e3 00 [2] 97 18 [2] d0 1a [2] 97 0b [2] d9 07 [2] d5 0d [2] c2 06 [2] d9 48 [2] e4 }

  condition:
    any of them
}