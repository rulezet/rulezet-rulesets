rule TTP_XOR_MULT_DOSStub_8155 {
  strings:
    $key_8155 = { d5 3d [2] a1 25 [2] e6 27 [2] a1 36 [2] ef 3a [2] e3 30 [2] f4 3b [2] ef 75 [2] d2 }

  condition:
    any of them
}