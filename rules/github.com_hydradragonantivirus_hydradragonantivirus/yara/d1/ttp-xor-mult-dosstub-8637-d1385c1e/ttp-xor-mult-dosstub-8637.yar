rule TTP_XOR_MULT_DOSStub_8637 {
  strings:
    $key_8637 = { d2 5f [2] a6 47 [2] e1 45 [2] a6 54 [2] e8 58 [2] e4 52 [2] f3 59 [2] e8 17 [2] d5 }

  condition:
    any of them
}