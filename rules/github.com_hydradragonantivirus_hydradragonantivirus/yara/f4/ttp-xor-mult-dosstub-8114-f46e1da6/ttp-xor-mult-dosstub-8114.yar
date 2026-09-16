rule TTP_XOR_MULT_DOSStub_8114 {
  strings:
    $key_8114 = { d5 7c [2] a1 64 [2] e6 66 [2] a1 77 [2] ef 7b [2] e3 71 [2] f4 7a [2] ef 34 [2] d2 }

  condition:
    any of them
}