rule TTP_XOR_MULT_DOSStub_8131 {
  strings:
    $key_8131 = { d5 59 [2] a1 41 [2] e6 43 [2] a1 52 [2] ef 5e [2] e3 54 [2] f4 5f [2] ef 11 [2] d2 }

  condition:
    any of them
}