rule TTP_XOR_MULT_DOSStub_83b1 {
  strings:
    $key_83b1 = { d7 d9 [2] a3 c1 [2] e4 c3 [2] a3 d2 [2] ed de [2] e1 d4 [2] f6 df [2] ed 91 [2] d0 }

  condition:
    any of them
}