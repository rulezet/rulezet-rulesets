rule TTP_XOR_MULT_DOSStub_8633 {
  strings:
    $key_8633 = { d2 5b [2] a6 43 [2] e1 41 [2] a6 50 [2] e8 5c [2] e4 56 [2] f3 5d [2] e8 13 [2] d5 }

  condition:
    any of them
}