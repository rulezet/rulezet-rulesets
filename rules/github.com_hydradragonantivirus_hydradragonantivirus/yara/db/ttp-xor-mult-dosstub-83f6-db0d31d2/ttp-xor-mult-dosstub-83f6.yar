rule TTP_XOR_MULT_DOSStub_83f6 {
  strings:
    $key_83f6 = { d7 9e [2] a3 86 [2] e4 84 [2] a3 95 [2] ed 99 [2] e1 93 [2] f6 98 [2] ed d6 [2] d0 }

  condition:
    any of them
}