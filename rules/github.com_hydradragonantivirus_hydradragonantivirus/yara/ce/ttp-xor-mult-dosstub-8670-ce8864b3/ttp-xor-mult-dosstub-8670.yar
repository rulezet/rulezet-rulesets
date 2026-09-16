rule TTP_XOR_MULT_DOSStub_8670 {
  strings:
    $key_8670 = { d2 18 [2] a6 00 [2] e1 02 [2] a6 13 [2] e8 1f [2] e4 15 [2] f3 1e [2] e8 50 [2] d5 }

  condition:
    any of them
}