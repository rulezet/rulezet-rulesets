rule TTP_XOR_MULT_DOSStub_8106 {
  strings:
    $key_8106 = { d5 6e [2] a1 76 [2] e6 74 [2] a1 65 [2] ef 69 [2] e3 63 [2] f4 68 [2] ef 26 [2] d2 }

  condition:
    any of them
}