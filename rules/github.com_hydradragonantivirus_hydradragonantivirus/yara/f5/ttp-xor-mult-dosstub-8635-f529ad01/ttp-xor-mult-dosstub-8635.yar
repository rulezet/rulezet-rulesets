rule TTP_XOR_MULT_DOSStub_8635 {
  strings:
    $key_8635 = { d2 5d [2] a6 45 [2] e1 47 [2] a6 56 [2] e8 5a [2] e4 50 [2] f3 5b [2] e8 15 [2] d5 }

  condition:
    any of them
}