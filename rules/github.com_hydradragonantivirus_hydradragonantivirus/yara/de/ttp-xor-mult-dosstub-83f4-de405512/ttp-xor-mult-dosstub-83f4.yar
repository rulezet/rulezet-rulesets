rule TTP_XOR_MULT_DOSStub_83f4 {
  strings:
    $key_83f4 = { d7 9c [2] a3 84 [2] e4 86 [2] a3 97 [2] ed 9b [2] e1 91 [2] f6 9a [2] ed d4 [2] d0 }

  condition:
    any of them
}