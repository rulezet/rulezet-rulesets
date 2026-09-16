rule TTP_XOR_MULT_DOSStub_81fb {
  strings:
    $key_81fb = { d5 93 [2] a1 8b [2] e6 89 [2] a1 98 [2] ef 94 [2] e3 9e [2] f4 95 [2] ef db [2] d2 }

  condition:
    any of them
}