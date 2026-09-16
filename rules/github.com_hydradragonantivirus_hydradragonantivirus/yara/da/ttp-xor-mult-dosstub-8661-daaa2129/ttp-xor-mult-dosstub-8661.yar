rule TTP_XOR_MULT_DOSStub_8661 {
  strings:
    $key_8661 = { d2 09 [2] a6 11 [2] e1 13 [2] a6 02 [2] e8 0e [2] e4 04 [2] f3 0f [2] e8 41 [2] d5 }

  condition:
    any of them
}