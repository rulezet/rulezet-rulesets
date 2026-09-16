rule TTP_XOR_MULT_DOSStub_8647 {
  strings:
    $key_8647 = { d2 2f [2] a6 37 [2] e1 35 [2] a6 24 [2] e8 28 [2] e4 22 [2] f3 29 [2] e8 67 [2] d5 }

  condition:
    any of them
}