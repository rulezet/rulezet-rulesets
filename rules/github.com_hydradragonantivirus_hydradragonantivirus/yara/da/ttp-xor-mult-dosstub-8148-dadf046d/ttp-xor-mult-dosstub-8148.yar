rule TTP_XOR_MULT_DOSStub_8148 {
  strings:
    $key_8148 = { d5 20 [2] a1 38 [2] e6 3a [2] a1 2b [2] ef 27 [2] e3 2d [2] f4 26 [2] ef 68 [2] d2 }

  condition:
    any of them
}