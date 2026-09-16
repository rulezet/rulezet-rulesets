rule TTP_XOR_MULT_DOSStub_8135 {
  strings:
    $key_8135 = { d5 5d [2] a1 45 [2] e6 47 [2] a1 56 [2] ef 5a [2] e3 50 [2] f4 5b [2] ef 15 [2] d2 }

  condition:
    any of them
}