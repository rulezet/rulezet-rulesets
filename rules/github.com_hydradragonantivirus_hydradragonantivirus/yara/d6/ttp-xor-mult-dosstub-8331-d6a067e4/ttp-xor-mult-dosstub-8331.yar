rule TTP_XOR_MULT_DOSStub_8331 {
  strings:
    $key_8331 = { d7 59 [2] a3 41 [2] e4 43 [2] a3 52 [2] ed 5e [2] e1 54 [2] f6 5f [2] ed 11 [2] d0 }

  condition:
    any of them
}