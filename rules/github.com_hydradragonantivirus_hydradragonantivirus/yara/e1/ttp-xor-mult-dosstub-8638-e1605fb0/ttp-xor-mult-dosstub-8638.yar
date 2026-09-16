rule TTP_XOR_MULT_DOSStub_8638 {
  strings:
    $key_8638 = { d2 50 [2] a6 48 [2] e1 4a [2] a6 5b [2] e8 57 [2] e4 5d [2] f3 56 [2] e8 18 [2] d5 }

  condition:
    any of them
}