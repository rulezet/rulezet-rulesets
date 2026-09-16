rule TTP_XOR_MULT_DOSStub_8119 {
  strings:
    $key_8119 = { d5 71 [2] a1 69 [2] e6 6b [2] a1 7a [2] ef 76 [2] e3 7c [2] f4 77 [2] ef 39 [2] d2 }

  condition:
    any of them
}