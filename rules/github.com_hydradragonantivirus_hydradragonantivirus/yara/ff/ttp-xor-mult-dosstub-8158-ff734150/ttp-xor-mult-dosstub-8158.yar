rule TTP_XOR_MULT_DOSStub_8158 {
  strings:
    $key_8158 = { d5 30 [2] a1 28 [2] e6 2a [2] a1 3b [2] ef 37 [2] e3 3d [2] f4 36 [2] ef 78 [2] d2 }

  condition:
    any of them
}