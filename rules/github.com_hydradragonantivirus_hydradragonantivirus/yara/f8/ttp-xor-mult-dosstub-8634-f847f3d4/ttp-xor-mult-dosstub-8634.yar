rule TTP_XOR_MULT_DOSStub_8634 {
  strings:
    $key_8634 = { d2 5c [2] a6 44 [2] e1 46 [2] a6 57 [2] e8 5b [2] e4 51 [2] f3 5a [2] e8 14 [2] d5 }

  condition:
    any of them
}